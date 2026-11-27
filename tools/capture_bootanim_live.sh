#!/usr/bin/env bash
# Capture actual window frames of isolated original animation execution.
# Returning from export 1 alone does not imply that the animation rendered.
set -euo pipefail
native="$(realpath "$1")"
inputs="$(realpath "$2")"
out="$(realpath -m "$3")"
mkdir -p "$out"
cd "$native"
export X360_BOOTANIM_FLAGS=0 X360_BOOTANIM_CONTROL=graceful_event
export SDL_AUDIODRIVER="${X360_BOOTANIM_AUDIO_DRIVER:-dummy}"
# Real supported guest video mode, chosen only by the software-runner test.
# The original firmware still queries the SDK display mode normally.
mode_width="${METRO_CAPTURE_WIDTH:-1280}"
mode_height="${METRO_CAPTURE_HEIGHT:-720}"
./metro_bootanim_live --title.game_root="$inputs" --title.entry=bootanim.xex \
  --ui.fullscreen=false --ui.window_width="$mode_width" --ui.window_height="$mode_height" \
  --ui.video_mode_width="$mode_width" --ui.video_mode_height="$mode_height" \
  > "$out/bootanim-live.log" 2>&1 &
pid=$!
trap 'kill -KILL "$pid" 2>/dev/null || true' EXIT
count=0;last_sample_time=-2
# Observe long enough for software Vulkan without determining the guest exit.
deadline=$((SECONDS+105))
while ((SECONDS<deadline)); do
    kill -0 "$pid" 2>/dev/null || break
    window="$(xdotool search --onlyvisible --pid "$pid" 2>/dev/null | head -1 || true)"
    if [[ -n "$window" ]] && ((count<20 && SECONDS-last_sample_time>=2)); then
        if import -window "$window" "$out/frame-$(printf '%03d' "$count").png" 2>/dev/null; then
            ((count+=1));last_sample_time=$SECONDS
        fi
    fi
    sleep 0.4
done
set +e
timed_out=false
if kill -0 "$pid" 2>/dev/null; then
    timed_out=true
    echo "BOOTANIM_CAPTURE deadline expired; guest did not exit" >> "$out/bootanim-live.log"
    # Do not invoke TitleRuntime termination on a still-running original
    # renderer; the previous SIGTERM itself caused an indirect-buffer assert.
    # Record the timeout as failure rather than mislabeling forced teardown
    # as a crash during original execution.
    kill -KILL "$pid" 2>/dev/null
    wait "$pid"
    status=$?
else
    wait "$pid"
    status=$?
fi
set -e
trap - EXIT
printf 'exit_code=%s\ncaptured_frames=%s\ntimed_out=%s\nanimation_visually_verified=false\naudio_audibly_verified=false\n' "$status" "$count" "$timed_out" > "$out/receipt.txt"
grep -E '^BOOTANIM_LIVE ' "$out/bootanim-live.log" | tee "$out/gates.txt" || true
printf 'requested_guest_mode=%sx%s\n' "$mode_width" "$mode_height" >> "$out/receipt.txt"
cat "$out/receipt.txt"
grep -q '^BOOTANIM_LIVE original_entry ' "$out/gates.txt"
grep -q '^BOOTANIM_LIVE presented_frames ' "$out/gates.txt"
grep -Fxq 'BOOTANIM_LIVE original_initial_update_event signaled' "$out/gates.txt"
grep -Eq '^BOOTANIM_LIVE control_return argument=0 flag_a=[01] flag_b=1$' "$out/gates.txt"
grep -q '^BOOTANIM_LIVE original_return ' "$out/gates.txt"
test "$count" -gt 0
test "$timed_out" = false
test "$status" -eq 0
