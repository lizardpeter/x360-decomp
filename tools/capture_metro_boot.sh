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
./dash_17559 --title.game_root="$root" --title.entry=dash.xex \
  --ui.title="Metro 17559 Native Boot" --ui.fullscreen=false \
  --ui.window_width=1280 --ui.window_height=720 \
  --gpu.driver=vulkan --gpu.vulkan.sparse_shared_memory=false --hid.mnk_mode=true \
  --log.level=info --log.flush_level=info > "$out/boot.log" 2>&1 &
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
import -window "$win" "$out/input-00-idle.png"
sleep 2
import -window "$win" "$out/input-01-idle.png"
# Use the real SDK's keyboard pad binding; never write guest input state.
read_frame() {
  grep -E '^METRO_BOOT frames [1-9][0-9]*$' "$out/boot.log" | tail -n 1 | awk '{print $3}' || true
}
pad_observed=0
for key in Right Left; do
  kill -0 "$pid" 2>/dev/null || exit 1
  line_start="$(wc -l < "$out/boot.log")"
  frame_before="$(read_frame)"
  xdotool keydown Shift_L
  xdotool keydown "$key"
  sleep 0.25
  xdotool keyup "$key"
  xdotool keyup Shift_L
  sleep 3
  frame_after="$(read_frame)"
  kill -0 "$pid" 2>/dev/null || exit 1
  import -window "$win" "$out/input-$key.png"
  printf 'input_key=Shift+%s frames_before=%s frames_after=%s\n' "$key" "$frame_before" "$frame_after" >> "$out/receipt.txt"
  if [[ "$frame_before" =~ ^[1-9][0-9]*$ && "$frame_after" =~ ^[1-9][0-9]*$ ]] && [ "$frame_after" -gt "$frame_before" ]; then
    # The keyboard bindings intentionally emit right/left D-pad bits.
    # Require a real press AND later release on the same guest context.
    expected=0008
    if [ "$key" = Left ]; then expected=0004; fi
    trace="$out/input-$key.log"
    tail -n "+$((line_start+1))" "$out/boot.log" | grep -F 'METRO_GUEST_PAD ' > "$trace" || true
    cat "$trace" >> "$out/receipt.txt"
    if awk -v wanted="$expected" '
      /context=10000001 user=0/ {
        if (index(tolower($0),"buttons=0x" wanted)) pressed=1
        else if (pressed && index(tolower($0),"buttons=0x0000")) released=1
      }
      END {exit !(pressed && released)}
    ' "$trace"; then
      pad_observed=$((pad_observed+1))
    fi
  fi
done
for file in "$out"/input-*.png; do
  (cd "$out" && sha256sum "$(basename "$file")") >> "$out/receipt.txt"
done
printf 'input_probes_with_frame_progress_and_pad_transition=%s\n' "$pad_observed" >> "$out/receipt.txt"
cat "$out/receipt.txt"
if [ "$pad_observed" -ne 2 ]; then
  echo "Guest-consumed pad transitions and frame progress have not been established for both probes." >&2
  exit 1
fi
echo "Captured actual guest-frame and input candidates; visual menu inspection is still required."
