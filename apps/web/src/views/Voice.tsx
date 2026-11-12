import { createResource, createSignal, For, onCleanup } from "solid-js";
import { haptic } from "../app/appearance";
import { Icon } from "../app/icons";
import type { AppState, MessageRow } from "../app/state";
import { strings } from "../app/strings";

/** krypt_wire::limits: a voice message's waveform and longest length. */
const WAVEFORM_LEN = 64;
const VOICE_MAX_MS = 15 * 60 * 1000;
const SPEEDS = [1, 1.5, 2];

const clock = (ms: number) => {
  const s = Math.max(0, Math.round(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};

/** Loudness samples resampled to the waveform's length, scaled to bytes. */
function waveform(levels: number[]): number[] {
  if (levels.length === 0) return new Array<number>(WAVEFORM_LEN).fill(0);
  const peak = Math.max(...levels, 1e-3);
  return Array.from({ length: WAVEFORM_LEN }, (_, i) => {
    const from = Math.floor((i * levels.length) / WAVEFORM_LEN);
    const to = Math.max(from + 1, Math.floor(((i + 1) * levels.length) / WAVEFORM_LEN));
    const level = Math.max(...levels.slice(from, to));
    return Math.min(255, Math.round((level / peak) * 255));
  });
}

/** A voice message: play and pause, its waveform filling as it plays, its
 * length, and the speed. */
export function VoiceBubble(props: { app: AppState; row: MessageRow }) {
  const voice = () => props.row.voice!;
  const file = () => props.row.file!;
  const [blob] = createResource(
    () => (file().state === "ready" ? file().id : undefined),
    (id) => props.app.rt.file(id),
  );
  const [url, setUrl] = createSignal<string>();
  const [playing, setPlaying] = createSignal(false);
  const [at, setAt] = createSignal(0);
  const [speed, setSpeed] = createSignal(0);
  let audio: HTMLAudioElement | undefined;
  onCleanup(() => {
    audio?.pause();
    const current = url();
    if (current) URL.revokeObjectURL(current);
  });

  const toggle = () => {
    const b = blob();
    if (!b) {
      if (file().state === "remote" || file().state === "failed") void props.app.rt.download(props.row);
      return;
    }
    if (!audio) {
      const src = URL.createObjectURL(b);
      setUrl(src);
      audio = new Audio(src);
      audio.playbackRate = SPEEDS[speed()]!;
      audio.ontimeupdate = () => setAt(audio!.currentTime * 1000);
      audio.onended = () => {
        setPlaying(false);
        setAt(0);
      };
      audio.onpause = () => setPlaying(false);
      audio.onplay = () => setPlaying(true);
    }
    haptic("tap");
    if (audio.paused) void audio.play();
    else audio.pause();
  };
  const cycle = () => {
    const next = (speed() + 1) % SPEEDS.length;
    setSpeed(next);
    if (audio) audio.playbackRate = SPEEDS[next]!;
    haptic("toggle");
  };
  const progress = () => Math.min(1, at() / Math.max(voice().durationMs, 1));
  const loading = () => file().state !== "ready" && file().state !== "remote" && file().state !== "failed";

  return (
    <div class="voice" classList={{ playing: playing() }}>
      <button
        class="voice-play press"
        aria-label={playing() ? strings.voice.pause : strings.voice.play}
        disabled={loading()}
        onClick={toggle}
      >
        <Icon name={playing() ? "pause" : "play"} size={20} />
      </button>
      <div class="voice-wave" aria-hidden="true" style={{ "--played": String(progress()) }}>
        <For each={voice().waveform}>
          {(level, i) => (
            <span
              classList={{ played: (i() + 0.5) / WAVEFORM_LEN <= progress() }}
              style={{ height: `${Math.max(12, Math.round((level / 255) * 100))}%` }}
            />
          )}
        </For>
      </div>
      <span class="meta voice-time">{clock(playing() || at() > 0 ? at() : voice().durationMs)}</span>
      <button class="voice-speed meta press" onClick={cycle}>
        {strings.voice.speed(SPEEDS[speed()]!)}
      </button>
    </div>
  );
}

/** Records a voice message: the microphone until Send (or Cancel), with the
 * time and a level meter. At most fifteen minutes, then it sends itself. */
export function Recorder(props: {
  onSend: (blob: Blob, durationMs: number, waveform: number[]) => void;
  onCancel: () => void;
  onError: (message: string) => void;
}) {
  const [elapsed, setElapsed] = createSignal(0);
  const [level, setLevel] = createSignal(0);
  const levels: number[] = [];
  const chunks: Blob[] = [];
  let recorder: MediaRecorder | undefined;
  let stream: MediaStream | undefined;
  let context: AudioContext | undefined;
  let frame = 0;
  let started = 0;
  let sending = false;

  const stopAll = () => {
    cancelAnimationFrame(frame);
    for (const track of stream?.getTracks() ?? []) track.stop();
    if (context && context.state !== "closed") void context.close().catch(() => {});
  };
  onCleanup(() => {
    if (recorder?.state === "recording") recorder.stop();
    stopAll();
  });

  const finish = (send: boolean) => {
    if (!recorder || recorder.state !== "recording") return;
    sending = send;
    recorder.stop();
  };

  void (async () => {
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
    } catch {
      props.onError(strings.voice.micDenied);
      return;
    }
    const type = MediaRecorder.isTypeSupported("audio/webm;codecs=opus") ? "audio/webm;codecs=opus" : "audio/mp4";
    recorder = new MediaRecorder(stream, { mimeType: type, audioBitsPerSecond: 32_000 });
    recorder.ondataavailable = (e) => {
      if (e.data.size > 0) chunks.push(e.data);
    };
    recorder.onstop = () => {
      stopAll();
      if (!sending) return props.onCancel();
      props.onSend(new Blob(chunks, { type }), Date.now() - started, waveform(levels));
    };
    context = new AudioContext();
    const analyser = context.createAnalyser();
    analyser.fftSize = 512;
    context.createMediaStreamSource(stream).connect(analyser);
    const samples = new Float32Array(analyser.fftSize);
    started = Date.now();
    recorder.start(1_000);
    haptic("tap");
    const tick = () => {
      analyser.getFloatTimeDomainData(samples);
      let sum = 0;
      for (const s of samples) sum += s * s;
      const rms = Math.sqrt(sum / samples.length);
      levels.push(rms);
      setLevel(Math.min(1, rms * 4));
      setElapsed(Date.now() - started);
      if (Date.now() - started >= VOICE_MAX_MS) return finish(true);
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
  })();

  return (
    <div class="recorder" role="status" aria-label={strings.voice.recording}>
      <button
        class="icon-btn"
        type="button"
        aria-label={strings.voice.cancel}
        onClick={() => {
          haptic("cancel");
          finish(false);
          if (!recorder) props.onCancel();
        }}
      >
        <Icon name="close" />
      </button>
      <span class="recorder-dot" aria-hidden="true" />
      <span class="meta recorder-time">{clock(elapsed())}</span>
      <span class="recorder-level" aria-hidden="true" style={{ "--level": String(level()) }} />
      <button
        class="send press"
        type="button"
        aria-label={strings.voice.send}
        onClick={() => {
          haptic("send");
          finish(true);
        }}
      >
        <Icon name="send" />
      </button>
    </div>
  );
}
