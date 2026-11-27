#!/usr/bin/env bash
# Measure the actual native host audio output on a private PulseAudio sink.
# Original audio samples stay in ignored build/ and are never uploaded.
set -euo pipefail
native="$(realpath "$1")"
inputs="$(realpath "$2")"
out="$(realpath -m "$3")"
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out" "$out/xdg"
chmod 700 "$out/xdg"
export XDG_RUNTIME_DIR="$out/xdg"
export PULSE_RUNTIME_PATH="$out/xdg/pulse"
export PULSE_SERVER="unix:$PULSE_RUNTIME_PATH/native"
mkdir -p "$PULSE_RUNTIME_PATH"
# No default host audio device or unrelated stream is included in the capture.
pulseaudio --daemonize=no --use-pid-file=no --exit-idle-time=-1 --log-target="file:$out/pulse.log" -n \
    -L "module-native-protocol-unix socket=$PULSE_RUNTIME_PATH/native auth-anonymous=1" &
pulse_pid=$!
recorder=""
cleanup() {
    if [[ -n "$recorder" ]]; then
        kill -INT "$recorder" 2>/dev/null || true
        wait "$recorder" 2>/dev/null || true
    fi
    kill "$pulse_pid" 2>/dev/null || true
    wait "$pulse_pid" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 30); do
    if pactl info > "$out/pulse-info.txt" 2>/dev/null; then break; fi
    sleep 0.2
done
if ! pactl info > "$out/pulse-info.txt"; then
    cat "$out/pulse.log" >&2 || true
    exit 1
fi
module="$(pactl load-module module-null-sink sink_name=metro_original_audio rate=48000 channels=2 sink_properties=device.description=MetroOriginalAudio)"
pactl set-default-sink metro_original_audio
pactl set-sink-mute metro_original_audio 0
pactl set-sink-volume metro_original_audio 100%
export PULSE_SINK=metro_original_audio
pactl list short sinks > "$out/sinks.txt"
pactl list short sink-inputs > "$out/before-inputs.txt"
test ! -s "$out/before-inputs.txt"
# parec records the actual mixed host device output, not the original XMA
# resource or a synthesized reference. Keep one second of silent baseline.
parec --raw --format=float32le --rate=48000 --channels=2 \
    --device=metro_original_audio.monitor > "$out/output.f32le" 2>"$out/parec.log" &
recorder=$!
sleep 1
kill -0 "$recorder"
export X360_BOOTANIM_AUDIO_DRIVER=pulseaudio
set +e
bash "$root/tools/capture_bootanim_live.sh" "$native" "$inputs" "$out/visual"
boot_status=$?
set -e
sleep 0.5
kill -INT "$recorder" 2>/dev/null || true
wait "$recorder" 2>/dev/null || true
recorder=""
pactl unload-module "$module"
python "$root/tools/bootanim_pcm_evidence.py" "$out/output.f32le" \
    --boot-exit "$boot_status" --output "$out/pcm-evidence.json"
cat "$out/pcm-evidence.json"
# Distinguish non-silent output from correct-sounding original audio. This
# gate establishes actual host PCM activity only; audible fidelity requires
# further reference comparison. A silent run must fail the audio gate.
python - "$out/pcm-evidence.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
if not (d["baseline_silent"] and d["non_silent_output"] and d["finite_samples"] and d["boot_exit"]==0):
    raise SystemExit("Original native PCM output not established")
PY
