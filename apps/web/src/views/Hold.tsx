import { createSignal, onCleanup, type JSX } from "solid-js";
import { haptic } from "../app/appearance";

const HOLD_MS = 2000;
const TICKS = 10;
/** Letting go drains a full bar in this long. */
const DRAIN_MS = 300;

type Phase = "idle" | "holding" | "draining" | "done";

/** A destructive action confirmed by holding: a bar fills the button, with a
 * tick at every tenth, a little stronger each time. Letting go early drains
 * it; holding to the end confirms. Space or Enter held down works the same. */
export function Hold(props: { label: string; holding: string; onConfirm: () => void; children?: JSX.Element }) {
  const [progress, setProgress] = createSignal(0);
  const [phase, setPhase] = createSignal<Phase>("idle");
  let frame = 0;
  let last = 0;
  let started = 0;
  let ticked = 0;

  const loop = (now: number) => {
    const dt = now - last;
    last = now;
    if (phase() === "holding") {
      const p = Math.min(1, (now - started) / HOLD_MS);
      setProgress(p);
      if (Math.floor(p * TICKS) > ticked) {
        ticked = Math.floor(p * TICKS);
        if (p < 1) haptic("progressTick", undefined, p);
      }
      if (p >= 1) {
        setPhase("done");
        haptic("burned");
        props.onConfirm();
      }
    } else if (phase() === "draining") {
      const p = Math.max(0, progress() - dt / DRAIN_MS);
      setProgress(p);
      if (p === 0) setPhase("idle");
    }
    frame = phase() === "holding" || phase() === "draining" ? requestAnimationFrame(loop) : 0;
  };

  const start = () => {
    if (phase() === "holding" || phase() === "done") return;
    // Pressed again while draining: carry on from where it is.
    started = performance.now() - progress() * HOLD_MS;
    ticked = Math.floor(progress() * TICKS);
    setPhase("holding");
    if (!frame) {
      last = performance.now();
      frame = requestAnimationFrame(loop);
    }
  };
  const stop = () => {
    if (phase() !== "holding") return;
    setPhase("draining");
    haptic("cancel");
  };
  onCleanup(() => cancelAnimationFrame(frame));

  return (
    <button
      class="btn danger hold"
      data-phase={phase()}
      style={{ "--progress": String(progress()) }}
      onPointerDown={(e) => {
        e.currentTarget.setPointerCapture(e.pointerId);
        start();
      }}
      onPointerUp={stop}
      onPointerCancel={stop}
      onKeyDown={(e) => {
        if ((e.key === " " || e.key === "Enter") && !e.repeat) {
          e.preventDefault();
          start();
        }
      }}
      onKeyUp={(e) => {
        if (e.key === " " || e.key === "Enter") stop();
      }}
      onContextMenu={(e) => e.preventDefault()}
    >
      <span class="hold-bar" aria-hidden="true" />
      {props.children}
      {phase() === "holding" || phase() === "done" ? props.holding : props.label}
    </button>
  );
}
