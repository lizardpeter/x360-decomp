#!/usr/bin/env bash
# Capture only the actual guest window after the SDK reports title frames.
# A captured candidate is NOT proof that the dashboard menu has loaded.
set -euo pipefail
if [ "$#" -ne 2 ]; then echo "usage: $0 HOST_BUILD_DIR RUNTIME_ROOT" >&2; exit 2; fi
native="$(realpath "$1")"
root="$(realpath "$2")"
out="$native/metro-capture"
mkdir -p "$out"
rm -f "$out"/candidate-*.png "$out/next.png" "$out/receipt.txt" "$out/boot.log"
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
  --gpu.driver=vulkan --gpu.vulkan.sparse_shared_memory=false \
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
for tick in $(seq 1 90); do
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
echo "Captured actual guest-frame candidates; visual inspection is still required."
