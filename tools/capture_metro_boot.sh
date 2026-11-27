#!/usr/bin/env bash
# Capture only the actual guest window after the SDK reports title frames.
# A captured candidate is NOT proof that the dashboard menu has loaded.
set -euo pipefail
if [ "$#" -ne 2 ]; then echo "usage: $0 HOST_BUILD_DIR RUNTIME_ROOT" >&2; exit 2; fi
native="$(realpath "$1")"
root="$(realpath "$2")"
out="$native/metro-capture"
mkdir -p "$out"
rm -f "$out"/candidate-*.png "$out"/input-*.png "$out/next.png" "$out/receipt.txt" "$out/boot.log"
export X360_METRO_BOOT=1
export SDL_AUDIODRIVER=dummy
export SDL_VIDEODRIVER=x11
export XDG_RUNTIME_DIR="$out/xdg"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
cd "$native"
profile_args=()
if [ "${X360_METRO_PROFILE_PROBE:-0}" = 1 ]; then
  # Synthetic input only: never mount a real local profile in CI.
  unset X360_METRO_LOCAL_PROFILES
  export X360_METRO_PROFILE_TRACE=1
  export X360_METRO_GUIDE_TRACE=1
  profile_args=(--hid.guide_button=true --hid.keybind_guide=F9)
fi
./dash_17559 --title.game_root="$root" --title.entry=dash.xex \
  --ui.title="Metro 17559 Native Boot" --ui.fullscreen=false \
  --ui.window_width=1280 --ui.window_height=720 \
  --gpu.driver=vulkan --gpu.vulkan.sparse_shared_memory=false --hid.mnk_mode=true \
  "${profile_args[@]}" --log.level=info --log.flush_level=info > "$out/boot.log" 2>&1 &
pid=$!
cleanup() {
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 124' TERM INT
# A splash screen may be the first nonblank frame. Retain a sequence of
# authentic, independently presented frames for visual menu inspection.
samples=0
last_frame=0
last_sample=0
: > "$out/receipt.txt"
printf 'menu_visually_verified=false\n' >> "$out/receipt.txt"
for tick in $(seq 1 65); do
  kill -0 "$pid" 2>/dev/null || break
  frame="$(grep -E '^METRO_BOOT frames [1-9][0-9]*$' "$out/boot.log" | tail -n 1 | awk '{print $3}' || true)"
  if grep -Fxq "METRO_BOOT pass dashboard_entry" "$out/boot.log" &&
     [[ "$frame" =~ ^[1-9][0-9]*$ ]] &&
     [ "$frame" -gt "$last_frame" ] &&
     { [ "$samples" -eq 0 ] || [ "$((tick-last_sample))" -ge 8 ]; }; then
    win="$(xdotool search --all --onlyvisible --pid "$pid" --name 'Metro 17559 Native Boot' 2>/dev/null | head -n 1 || true)"
    if [ -n "$win" ] && import -window "$win" "$out/next.png" 2>/dev/null; then
      info="$(identify -format '%w %h %k' "$out/next.png" 2>/dev/null || true)"
      if read -r width height colors <<< "$info" &&
         [[ "$width" =~ ^[0-9]+$ && "$height" =~ ^[0-9]+$ && "$colors" =~ ^[0-9]+$ ]] &&
         [ "$width" -ge 640 ] && [ "$height" -ge 360 ] && [ "$colors" -ge 32 ] &&
         kill -0 "$pid" 2>/dev/null; then
        samples=$((samples+1))
        last_sample="$tick"
        last_frame="$frame"
        name="$(printf 'candidate-%02d.png' "$samples")"
        mv "$out/next.png" "$out/$name"
        printf 'sample=%s guest_frames=%s width=%s height=%s colors=%s\n' \
          "$name" "$frame" "$width" "$height" "$colors" >> "$out/receipt.txt"
        (cd "$out" && sha256sum "$name") >> "$out/receipt.txt"
        if [ "$samples" -ge 4 ]; then break; fi
      fi
    fi
  fi
  sleep 1
done
printf 'captured_samples=%s\n' "$samples" >> "$out/receipt.txt"
grep -E '^METRO_BOOT (pass|fail|frames|guest_exit)' "$out/boot.log" >> "$out/receipt.txt" || true
cat "$out/receipt.txt"
if [ "$samples" -eq 0 ]; then
  echo "No live, nonblank title-frame candidate captured." >&2
  tail -n 100 "$out/boot.log" >&2
  exit 1
fi
if ! kill -0 "$pid" 2>/dev/null; then
  echo "Guest exited before capture completed; candidates are diagnostic only." >&2
  tail -n 100 "$out/boot.log" >&2
  exit 1
fi
# The candidate series must be complete, not just one animated splash frame.
if [ "$samples" -ne 4 ]; then
  echo "Only $samples of four genuine live frame candidates captured." >&2
  exit 1
fi
printf 'navigation_visually_verified=false\n' >> "$out/receipt.txt"
win="$(xdotool search --all --onlyvisible --pid "$pid" --name 'Metro 17559 Native Boot' 2>/dev/null | head -n 1 || true)"
if [ -z "$win" ] || ! xdotool windowfocus --sync "$win"; then
  echo "Could not focus original dashboard window for navigation probe." >&2
  exit 1
fi
# Test both axes; a blocked direction is not itself an input failure.
read_frame() {
  grep -E '^METRO_BOOT frames [1-9][0-9]*$' "$out/boot.log" | tail -n 1 | awk '{print $3}' || true
}
wait_frames() {
  local before="$1" delta="$2" after
  [[ "$before" =~ ^[0-9]+$ ]] || return 1
  for _ in $(seq 1 12); do
    kill -0 "$pid" 2>/dev/null || return 1
    after="$(read_frame)"
    if [[ "$after" =~ ^[0-9]+$ ]] && ((after>=before+delta)); then
      printf '%s' "$after"; return 0
    fi
    sleep 0.5
  done
  return 1
}
difference() {
  local count status=0
  count="$(compare -fuzz 2% -metric AE "$1" "$2" null: 2>&1)" || status=$?
  if ((status>1)) || ! [[ "$count" =~ ^[0-9]+$ ]]; then return 1; fi
  printf '%s' "$count"
}
pad_observed=0
visual_changes=0
reversible_pairs=0
for axis in vertical horizontal; do
  if [[ "$axis" == vertical ]]; then first=Down; second=Up; else first=Right; second=Left; fi
  pair="$out/input-$axis"
  before="$(read_frame)"
  import -window "$win" "$pair-idle-a.png"
  wait_frames "$before" 5 >/dev/null || exit 1
  import -window "$win" "$pair-idle-b.png"
  idle="$(difference "$pair-idle-a.png" "$pair-idle-b.png")" || exit 1
  previous="$pair-idle-b.png"
  threshold=$((idle*3+64))
  first_settled=0
  for key in "$first" "$second"; do
    kill -0 "$pid" 2>/dev/null || exit 1
    line_start="$(wc -l < "$out/boot.log")"
    frame_before="$(read_frame)"
    xdotool keydown Shift_L
    xdotool keydown "$key"
    sleep 0.25
    xdotool keyup "$key"
    xdotool keyup Shift_L
    frame_after="$(wait_frames "$frame_before" 10)" || exit 1
    image="$out/input-$key.png"
    import -window "$win" "$image"
    # Original animations can take longer than 15 frames, especially on
    # software Vulkan. Sample until two consecutive intervals are stable,
    # not a fixed delay. Preserve each real captured frame.
    settled_frame="$frame_after"
    stable="$out/input-$key-settled.png"
    prior="$image"
    streak=0
    motion=0
    for sample in $(seq 1 8); do
      settled_frame="$(wait_frames "$settled_frame" 5)" || exit 1
      next="$out/input-$key-motion-$sample.png"
      import -window "$win" "$next"
      motion="$(difference "$prior" "$next")" || exit 1
      if ((motion<=threshold)); then streak=$((streak+1)); else streak=0; fi
      prior="$next"
      if ((streak>=2)); then break; fi
    done
    cp "$prior" "$stable"
    changed="$(difference "$previous" "$stable")" || exit 1
    restored="$(difference "$pair-idle-b.png" "$stable")" || exit 1
    printf 'input_key=Shift+%s frames_before=%s frames_after=%s settled_frame=%s idle_noise=%s changed_pixels=%s settling_pixels=%s from_pair_baseline=%s threshold=%s stable_intervals=%s\n' \
      "$key" "$frame_before" "$frame_after" "$settled_frame" "$idle" "$changed" "$motion" "$restored" "$threshold" "$streak" >> "$out/receipt.txt"
    case "$key" in
      Up) expected=0001;; Down) expected=0002;; Left) expected=0004;; Right) expected=0008;;
    esac
    trace="$out/input-$key.log"
    tail -n "+$((line_start+1))" "$out/boot.log" | grep -F 'METRO_GUEST_PAD ' > "$trace" || true
    cat "$trace" >> "$out/receipt.txt"
    if awk -v wanted="$expected" '
      /context=10000001 user=0/ {
        if (index(tolower($0),"buttons=0x" wanted)) pressed=1
        else if (pressed && index(tolower($0),"buttons=0x0000")) released=1
      }
      END {exit !(pressed && released)}
    ' "$trace"; then pad_observed=$((pad_observed+1)); fi
    if ((streak>=2 && changed>threshold && motion<=threshold)); then
      visual_changes=$((visual_changes+1))
      if [[ "$key" == "$first" ]]; then first_settled=1; fi
    fi
    if [[ "$key" == "$second" ]] && ((first_settled && streak>=2 && changed>threshold && motion<=threshold && restored<=threshold)); then
      reversible_pairs=$((reversible_pairs+1))
    fi
    previous="$stable"
  done
done
for file in "$out"/input-*.png; do
  (cd "$out" && sha256sum "$(basename "$file")") >> "$out/receipt.txt"
done
printf 'input_probes_with_frame_progress_and_pad_transition=%s\ninput_probes_with_stable_visual_changes=%s\ninput_reversible_visual_pairs=%s\n' \
  "$pad_observed" "$visual_changes" "$reversible_pairs" >> "$out/receipt.txt"
cat "$out/receipt.txt"
if ((pad_observed!=4)); then
  echo "Not all four directions reached the original guest." >&2; exit 1
fi
if ((reversible_pairs<1)); then
  echo "No stable reversible visual navigation candidate yet." >&2; exit 1
fi
echo "Captured real guest input and reversible visual candidates; menu/navigation still require visual inspection."

# The optional original Guide test runs only after the four reversible
# dashboard directions. No sign-in API is injected, no account is created.
if [ "${X360_METRO_PROFILE_PROBE:-0}" = 1 ]; then
  line_start="$(wc -l < "$out/boot.log")"
  baseline="$(read_frame)"
  import -window "$win" "$out/input-profile-before.png"
  xdotool keydown F9
  sleep 0.25
  xdotool keyup F9
  after="$(wait_frames "$baseline" 10)" || exit 1
  for n in $(seq 1 4); do
    after="$(wait_frames "$after" 5)" || exit 1
    import -window "$win" "$out/input-profile-guide-$n.png"
  done
  change="$(difference "$out/input-profile-before.png" "$out/input-profile-guide-4.png")" || exit 1
  tail -n "+$((line_start+1))" "$out/boot.log" | grep -E 'METRO_GUEST_PAD|METRO_PROFILE_TRACE|METRO_PROFILE module=|METRO_GUIDE_TRACE|METRO_SYSREQ' > "$out/profile-guide.log" || true
  # B is a cancel request. Never send A/confirm at an unknown account dialog.
  xdotool keydown BackSpace
  sleep 0.25
  xdotool keyup BackSpace
  after="$(wait_frames "$after" 10)" || exit 1
  for n in $(seq 1 3); do
    after="$(wait_frames "$after" 5)" || exit 1
    import -window "$win" "$out/input-profile-cancel-$n.png"
  done
  restore="$(difference "$out/input-profile-before.png" "$out/input-profile-cancel-3.png")" || exit 1
  tail -n "+$((line_start+1))" "$out/boot.log" | grep -E 'METRO_GUEST_PAD|METRO_PROFILE_TRACE|METRO_PROFILE module=|METRO_GUIDE_TRACE|METRO_SYSREQ' > "$out/profile-guide.log" || true
  cat "$out/profile-guide.log" >> "$out/receipt.txt"
  guide=0
  cancel=0
  if awk '/context=10000001 user=0/ {if (index(tolower($0),"buttons=0x0400")) p=1;else if (p && index(tolower($0),"buttons=0x0000")) r=1} END {exit !(p && r)}' "$out/profile-guide.log"; then guide=1; fi
  if awk '/context=10000001 user=0/ {if (index(tolower($0),"buttons=0x2000")) p=1;else if (p && index(tolower($0),"buttons=0x0000")) r=1} END {exit !(p && r)}' "$out/profile-guide.log"; then cancel=1; fi
  printf 'profile_guide_pad_transition=%s\nprofile_cancel_pad_transition=%s\nprofile_guide_changed_pixels=%s\nprofile_cancel_from_baseline=%s\nprofile_guest_ui_visually_verified=false\nprofile_signed_in=false\n' "$guide" "$cancel" "$change" "$restore" >> "$out/receipt.txt"
  for file in "$out"/input-profile-*.png; do
    (cd "$out" && sha256sum "$(basename "$file")") >> "$out/receipt.txt"
  done
  tail -n 8 "$out/receipt.txt"
  if ((guide!=1 || cancel!=1)); then
    echo "Guide or cancel did not reach original guest." >&2
    exit 1
  fi
fi
