#!/usr/bin/env bash
# Capture actual window frames of isolated original animation execution.
# Returning from export 1 alone does not imply that the animation rendered.
set -euo pipefail
native="$(realpath "$1")"
inputs="$(realpath "$2")"
out="$(realpath -m "$3")"
mkdir -p "$out"
cd "$native"
export X360_BOOTANIM_FLAGS=0 X360_BOOTANIM_CONTROL=two_phase
export SDL_AUDIODRIVER="${X360_BOOTANIM_AUDIO_DRIVER:-dummy}"
./metro_bootanim_live --title.game_root="$inputs" --title.entry=bootanim.xex > "$out/bootanim-live.log" 2>&1 &
pid=$!
trap 'kill -KILL "$pid" 2>/dev/null || true' EXIT
count=0
deadline=$((SECONDS+52))
while ((SECONDS<deadline)); do
    kill -0 "$pid" 2>/dev/null || break
    window="$(xdotool search --onlyvisible --pid "$pid" 2>/dev/null | head -1 || true)"
    if [[ -n "$window" ]]; then
        if import -window "$window" "$out/frame-$(printf '%03d' "$count").png" 2>/dev/null; then
            ((count+=1))
        fi
    fi
    sleep 0.15
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
cat "$out/receipt.txt"
grep -q '^BOOTANIM_LIVE original_entry ' "$out/gates.txt"
grep -q '^BOOTANIM_LIVE presented_frames ' "$out/gates.txt"
grep -q '^BOOTANIM_LIVE original_return ' "$out/gates.txt"
test "$count" -gt 0
test "$timed_out" = false
test "$status" -eq 0
