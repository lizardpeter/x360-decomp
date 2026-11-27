#!/usr/bin/env bash
# Separately verify the original animation -> original XAM -> dashboard
# sequence. Never count intro screenshots as dashboard screenshots.
set -euo pipefail
native="$(realpath "$1")"
root="$(realpath "$2")"
out="$(realpath -m "$3")"
mkdir -p "$out/xdg"
chmod 700 "$out/xdg"
export XDG_RUNTIME_DIR="$out/xdg" SDL_AUDIODRIVER=dummy SDL_VIDEODRIVER=x11
export X360_METRO_BOOT=1 X360_METRO_INTRO=1
mode_width="${METRO_CAPTURE_WIDTH:-1280}"
mode_height="${METRO_CAPTURE_HEIGHT:-720}"
cd "$native"
./dash_17559 --title.game_root="$root" --title.entry=dash.xex \
  --ui.title="Metro integrated original boot" --ui.fullscreen=false \
  --ui.window_width="$mode_width" --ui.window_height="$mode_height" \
  --ui.video_mode_width="$mode_width" --ui.video_mode_height="$mode_height" \
  --gpu.driver=vulkan --gpu.vulkan.sparse_shared_memory=false \
  --hid.mnk_mode=true --log.level=info --log.flush_level=info > "$out/integrated.log" 2>&1 &
pid=$!
trap 'kill -KILL "$pid" 2>/dev/null || true' EXIT
intro=0;dash=0;last_intro=0;last_dash=0
last_sample_time=-2
# This is a diagnostic observation budget, not a guest handoff deadline.
: > "$out/dashboard-samples.txt"
deadline=$((SECONDS+110))
while ((SECONDS<deadline)); do
    kill -0 "$pid" 2>/dev/null || break
    win="$(xdotool search --onlyvisible --pid "$pid" 2>/dev/null | head -1 || true)"
    if [[ -n "$win" ]]; then
        frame="$(grep -E '^METRO_INTRO frames [0-9]+$' "$out/integrated.log" | tail -1 | awk '{print $3}' || true)"
        if [[ "$frame" =~ ^[0-9]+$ ]] && ((frame>=last_intro+4 && intro<12 && SECONDS-last_sample_time>=2)) &&
           ! grep -Fq 'METRO_INTRO original_return ' "$out/integrated.log"; then
            if import -window "$win" "$out/intro-$(printf '%03d' "$intro").png" 2>/dev/null; then
                intro=$((intro+1));last_intro="$frame";last_sample_time=$SECONDS
            fi
        fi
        frame="$(grep -E '^METRO_INTRO post_handoff_frames [0-9]+$' "$out/integrated.log" | tail -1 | awk '{print $3}' || true)"
        if [[ "$frame" =~ ^[0-9]+$ ]] && ((frame>=last_dash+5 && dash<4)) &&
           grep -Fxq 'METRO_BOOT pass dashboard_entry' "$out/integrated.log"; then
            # A surface with only the previous intro or blank pixels cannot
            # be counted as a successful dashboard capture. Keep authentic
            # candidates only with actual post-attach counter advancement.
            if import -window "$win" "$out/dashboard-next.png" 2>/dev/null; then
                info="$(identify -format '%w %h %k' "$out/dashboard-next.png" 2>/dev/null || true)"
                if read -r width height colors <<< "$info" &&
                   [[ "$width" =~ ^[0-9]+$ && "$height" =~ ^[0-9]+$ && "$colors" =~ ^[0-9]+$ ]] &&
                   ((width>=640 && height>=360 && colors>=32)); then
                    name="dashboard-$(printf '%03d' "$dash").png"
                    mv "$out/dashboard-next.png" "$out/$name"
                    printf 'sample=%s post_attach_frames=%s width=%s height=%s colors=%s\n' \
                        "$name" "$frame" "$width" "$height" "$colors" >> "$out/dashboard-samples.txt"
                    dash=$((dash+1));last_dash="$frame"
                else
                    rm -f "$out/dashboard-next.png"
                fi
            fi
        fi
    fi
    if ((dash>=4)); then break; fi
    sleep 0.4
done
alive=false
if kill -0 "$pid" 2>/dev/null; then
    alive=true
    # No forced guest-shutdown assertion is confused with a boot fault.
    kill -KILL "$pid" 2>/dev/null || true
fi
set +e
wait "$pid"; status=$?
set -e
trap - EXIT
printf 'intro_frames=%s\npost_handoff_frames=%s\nalive_at_capture_end=%s\nexit_code=%s\nmenu_visually_verified=false\naudio_audibly_verified=false\n' \
  "$intro" "$dash" "$alive" "$status" > "$out/receipt.txt"
grep -E '^METRO_(INTRO|BOOT) (pass|fail|original_entry|original_return|original_initial_update_event|post_handoff_frames|guest_exit)' "$out/integrated.log" >> "$out/receipt.txt" || true
printf 'requested_guest_mode=%sx%s\n' "$mode_width" "$mode_height" >> "$out/receipt.txt"
cat "$out/dashboard-samples.txt" >> "$out/receipt.txt"
cat "$out/receipt.txt"
for gate in "METRO_INTRO pass loaded_as_user_module" "METRO_INTRO pass original_completion" "METRO_BOOT pass xam_attach" "METRO_BOOT pass dashboard_entry"; do
    grep -Fxq "$gate" "$out/integrated.log"
done
test "$intro" -gt 0
test "$dash" -eq 4
test "$alive" = true

# Require the original event and original graceful-control return, in order.
# A successful visual capture cannot excuse a missing lifecycle transition.
python - "$out/integrated.log" <<'PY'
import sys
from pathlib import Path
lines=Path(sys.argv[1]).read_text(errors="replace").splitlines()
def first(prefix):
    return next((i for i,l in enumerate(lines) if l.startswith(prefix)),None)
events=[first(p) for p in (
    "METRO_INTRO original_entry ",
    "METRO_INTRO original_initial_update_event signaled",
    "METRO_INTRO pass control_return argument=0 flag_b=1",
    "METRO_INTRO pass original_completion",
    "METRO_BOOT pass xam_attach",
    "METRO_BOOT pass dashboard_entry",
)]
if any(x is None for x in events) or events!=sorted(set(events)):
    raise SystemExit("Original event-driven intro lifecycle not verified")
print("Original event-driven intro lifecycle verified; visual/audio fidelity remains unverified.")
PY
