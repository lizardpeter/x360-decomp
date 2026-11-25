#!/usr/bin/env bash
# Capture only the actual guest window after the SDK reports title frames.
# A captured candidate is NOT proof that the dashboard menu has loaded.
set -euo pipefail
if [ "$#" -ne 2 ]; then echo "usage: $0 HOST_BUILD_DIR RUNTIME_ROOT" >&2; exit 2; fi
native="$(realpath "$1")"
root="$(realpath "$2")"
out="$native/metro-capture"
mkdir -p "$out"
rm -f "$out/candidate.png" "$out/receipt.txt" "$out/boot.log"
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
  --log.level=info > "$out/boot.log" 2>&1 &
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
for _ in $(seq 1 90); do
  kill -0 "$pid" 2>/dev/null || break
  if grep -Fxq "METRO_BOOT pass dashboard_entry" "$out/boot.log" &&
     grep -Eq '^METRO_BOOT frames [1-9][0-9]*$' "$out/boot.log"; then
    win="$(xdotool search --all --onlyvisible --pid "$pid" --name 'Metro 17559 Native Boot' 2>/dev/null | head -n 1 || true)"
    if [ -n "$win" ]; then
      if import -window "$win" "$out/next.png" 2>/dev/null; then
        read -r width height colors < <(identify -format '%w %h %k\n' "$out/next.png")
        if [ "$width" -ge 640 ] && [ "$height" -ge 360 ] && [ "$colors" -ge 32 ] &&
           kill -0 "$pid" 2>/dev/null; then
          mv "$out/next.png" "$out/candidate.png"
          printf 'width=%s\nheight=%s\ncolors=%s\nmenu_visually_verified=false\n' "$width" "$height" "$colors" > "$out/receipt.txt"
          sha256sum "$out/candidate.png" >> "$out/receipt.txt"
          grep -E '^METRO_BOOT (pass|frames) ' "$out/boot.log" >> "$out/receipt.txt"
          cat "$out/receipt.txt"
          exit 0
        fi
      fi
    fi
  fi
  sleep 1
done
echo "No live, nonblank title-frame candidate captured." >&2
tail -n 80 "$out/boot.log" >&2
exit 1
