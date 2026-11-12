// Haptics in the Android app (loaded there only): each theme's pattern from
// design/tokens, played pulse by pulse through the platform's haptic
// feedback (tauri-plugin-haptics) instead of a raw vibration. The events
// and their feel per theme are in docs/design-system.md, "Haptic vocabulary".
//
// - A transient pulse is an impact, chosen as the design system's Android
//   rule chooses a primitive: heavy from intensity 0.8; from 0.5, rigid when
//   sharp (sharpness 0.6 and up), else medium; below that, light, or soft
//   when dull (under 0.3).
// - A continuous pulse vibrates for its duration.
// - toggle and progressTick are selection feedback, the platform's own tick
//   for a discrete change: a switch flipped, a tenth of a hold.
// - Notification feedback is not used: success, cancel and burned have a
//   pattern of their own in each theme, which the theme picker previews.
//
// Like navigator.vibrate, a haptic replaces any still playing.

import { impactFeedback, selectionFeedback, vibrate, type ImpactFeedbackStyle } from "@tauri-apps/plugin-haptics";
import { pulses, type Pulse } from "../generated/haptics";
import type { Haptic, ThemeId } from "../generated/themes";

/** The longest pattern in the tokens has four pulses. */
const PULSES_MAX = 8;
/** Longer is a ring tone, which repeats rather than holds. */
const CONTINUOUS_MAX_MS = 1_000;

const SELECTION: ReadonlySet<Haptic> = new Set<Haptic>(["toggle", "progressTick"]);

/** Pulses of the playing haptic that are still to come. */
const pending: ReturnType<typeof setTimeout>[] = [];

function impactStyle(pulse: Pulse): ImpactFeedbackStyle {
  if (pulse.intensity >= 0.8) return "heavy";
  if (pulse.intensity >= 0.5) return pulse.sharpness >= 0.6 ? "rigid" : "medium";
  return pulse.sharpness < 0.3 ? "soft" : "light";
}

function play(pulse: Pulse) {
  const done =
    pulse.kind === "continuous"
      ? vibrate(Math.min(pulse.durationMs, CONTINUOUS_MAX_MS))
      : impactFeedback(impactStyle(pulse));
  // Haptics always accompany something visible; a failed one is just missed.
  done.catch(() => {});
}

export function playHaptic(name: Haptic, theme: ThemeId) {
  for (const timer of pending.splice(0)) clearTimeout(timer);
  if (SELECTION.has(name)) {
    selectionFeedback().catch(() => {});
    return;
  }
  const pattern = pulses[theme][name];
  console.assert(pattern.length <= PULSES_MAX, `haptic ${name}: ${pattern.length} pulses`);
  for (const pulse of pattern.slice(0, PULSES_MAX)) {
    if (pulse.t === 0) play(pulse);
    else pending.push(setTimeout(() => play(pulse), pulse.t));
  }
}
