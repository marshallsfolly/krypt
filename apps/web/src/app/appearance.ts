// Theme, mode, accent and haptics: a per-device preference, kept in
// localStorage (which may be unavailable; everything has a default).

import { createEffect, createRoot, createSignal } from "solid-js";
import { themes, type Haptic, type Theme, type ThemeId } from "../generated/themes";
import { android } from "./platform";

export type Mode = "system" | "light" | "dark";

interface Saved {
  theme: ThemeId;
  mode: Mode;
  accent: Record<string, string>;
  haptics: boolean;
}

const KEY = "krypt.appearance";
const fallback = themes.find((t) => t.isDefault)!;

function load(): Saved {
  const saved: Saved = { theme: fallback.id, mode: "system", accent: {}, haptics: true };
  try {
    Object.assign(saved, JSON.parse(localStorage.getItem(KEY) ?? "{}"));
  } catch {
    // Private windows and blocked storage: defaults.
  }
  if (!themes.some((t) => t.id === saved.theme)) saved.theme = fallback.id;
  return saved;
}

const dark = window.matchMedia("(prefers-color-scheme: dark)");

export const appearance = createRoot(() => {
  const [saved, setSaved] = createSignal(load());
  const [systemDark, setSystemDark] = createSignal(dark.matches);
  dark.addEventListener("change", (e) => setSystemDark(e.matches));

  const theme = (): Theme => themes.find((t) => t.id === saved().theme) ?? fallback;
  const accent = () => {
    const t = theme();
    const chosen = saved().accent[t.id];
    return t.accents.some((a) => a.id === chosen) ? chosen! : t.defaultAccent;
  };
  const mode = (): "light" | "dark" => {
    const m = saved().mode;
    return m === "system" ? (systemDark() ? "dark" : "light") : m;
  };

  const update = (change: Partial<Saved>) => {
    const next = { ...saved(), ...change };
    setSaved(next);
    try {
      localStorage.setItem(KEY, JSON.stringify(next));
    } catch {
      // Not remembered, but still applied.
    }
  };

  createEffect(() => {
    const root = document.documentElement;
    const t = theme();
    root.dataset.theme = t.id;
    root.dataset.mode = mode();
    root.dataset.accent = accent();
    for (const [name, value] of Object.entries(t.components)) root.dataset[name] = value;
    root.dataset.glow = String(t.ambientGlow);
  });

  return {
    theme,
    accent,
    mode,
    savedMode: () => saved().mode,
    haptics: () => saved().haptics,
    setTheme: (id: ThemeId) => update({ theme: id }),
    setAccent: (id: string) => update({ accent: { ...saved().accent, [theme().id]: id } }),
    setMode: (m: Mode) => update({ mode: m }),
    setHaptics: (on: boolean) => update({ haptics: on }),
  };
});

/** The Android app's native haptics, loaded there only (and at start, so
 * the first haptic is not late). */
const nativeHaptics = android ? import("./haptics") : undefined;

/** Safari on iPhone has no vibration API, but flipping a switch control
 * plays the system's selection tick (iOS 18), even one that is not shown. */
let iosSwitch: HTMLLabelElement | null | undefined;
const iosTicks: ReturnType<typeof setTimeout>[] = [];

function switchTick() {
  if (iosSwitch === undefined) {
    const input = document.createElement("input");
    iosSwitch = null;
    if (!("switch" in input)) return;
    input.type = "checkbox";
    input.setAttribute("switch", "");
    const label = document.createElement("label");
    label.setAttribute("aria-hidden", "true");
    label.style.display = "none";
    label.append(input);
    document.body.append(label);
    iosSwitch = label;
  }
  iosSwitch?.click();
}

/** Plays a semantic haptic in the current theme's style, where the device
 * can: Android browsers vibrate the pattern; Safari on iPhone ticks once per
 * pulse; the Android app gets native haptics. `strength` (0–1, a hold's
 * progress) lengthens the pulses of haptics that scale with it. Haptics
 * always accompany something visible; they are never the only signal. */
export function haptic(name: Haptic, theme: Theme = appearance.theme(), strength = 0) {
  if (!appearance.haptics()) return;
  if (nativeHaptics) {
    void nativeHaptics.then((h) => h.playHaptic(name, theme.id));
    return;
  }
  const scale = theme.scaling.includes(name) ? 1 + 2 * Math.min(1, Math.max(0, strength)) : 1;
  const pattern = theme.haptics[name].map((ms, i) => (i % 2 === 0 ? Math.round(ms * scale) : ms));
  if (pattern.length === 0) return;
  if ("vibrate" in navigator) {
    // Browsers only vibrate once the user has interacted with the page.
    if (navigator.userActivation && !navigator.userActivation.hasBeenActive) return;
    navigator.vibrate(pattern);
    return;
  }
  // Like a vibration, a haptic replaces one still playing.
  for (const tick of iosTicks.splice(0)) clearTimeout(tick);
  switchTick();
  let at = 0;
  for (let i = 2; i < pattern.length; i += 2) {
    at += pattern[i - 2]! + pattern[i - 1]!;
    iosTicks.push(setTimeout(switchTick, at));
  }
}

export { themes };
