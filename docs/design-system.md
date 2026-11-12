# krypt design system

krypt ships three themes. The user picks one, and **Obsidian Glass** is the default.

| Theme | Character | Accents |
|---|---|---|
| **Obsidian Glass** (`glass`, default) | Dark-first, translucent depth, one electric accent | mint · ice · violet · amber |
| **Swiss Mono** (`swiss`) | No bubbles. Strict grid, mono metadata, black and white plus one signal color | signal · cobalt · acid · red |
| **Soft Expressive** (`soft`) | Tonal color, big radii, spring physics, shapes that morph when pressed | violet · coral · teal · blue |

Every theme works in light and dark. The interactive prototypes are in
`prototypes/design/` and published at https://claude.ai/artifact/KbSBFKwLS7aVDDWDJ1UCsY.

## Source of truth

`design/tokens/{glass,swiss,soft}.json` holds all values. Platform code is generated
from these files and never edited by hand:

- the web client gets CSS custom properties and TypeScript types
- Apple platforms get Swift `Theme` values plus AHAP haptic files
- Android gets Kotlin objects plus `VibrationEffect` compositions

`nix flake check` runs `design/tokens/check.sh`. It requires:
- every theme defines exactly the same tokens
- every `{reference}` resolves
- exactly one theme is the default
- every haptic pattern is well formed

## What a theme may change, and what it may not

Themes are **presentation only**. A theme may change:

- color, type, radii, borders and material (blur)
- motion profile and haptic patterns
- structural variants of a few components (`components` in the tokens, below)

A theme may **not** change:

- **Information architecture, navigation, or copy.** There is one string table, so
  localization isn't tripled. Swiss uppercases labels through the type scale's `case`, not
  through separate strings.
- **Security state visibility.** Verification status, encryption state and, during calls,
  the connection path (direct or relayed) must be equally prominent in every theme. A
  theme must never make a security signal subtle.
- **Hit targets.** Minimum 44×44 pt in every theme.
- **Contrast.** Text is at least 4.5:1 and non-text UI at least 3:1, in both modes, for
  every accent. Each accent carries its own `on` color, plus an `ink` color for when the
  accent is used as text.
- **Haptic semantics.** The same events fire at the same moments. Only how they feel
  differs.

## Token groups

- **`accents`**: `{ value, on, ink: { light, dark } }`. Color tokens may reference
  `{accent}`, `{accent.on}`, `{accent.ink}`, or another token in the same mode, such as
  `{fg}`.
- **`color.{light,dark}`**: `bg`, `surface`, `surfaceRaised`, `line`, `fg`, `fgMuted`,
  `danger`, `onDanger`, `positive`, `onPositive`, `scrim`.
- **`material`**: background blur and saturation (Glass only), plus the ambient glow.
- **`type`**: font families plus a seven-step scale: display, title, headline, body,
  caption, label and meta. Sizes are in pt/px, tracking in em, and `case` is `none` or
  `upper`.
- **`shape`**: the radius scale, the bubble radius and tail, `pressedRadius` (Soft's
  press-to-morph), and border width.
- **`components`**: the structural variants each platform implements once:

  | Token | glass | swiss | soft |
  |---|---|---|---|
  | `message` | bubble | row (time column, sender label) | bubble |
  | `bubbleFill` | glass | none | tonal |
  | `avatar` | circle | none (name is display type) | blob, slowly morphing |
  | `control` | rounded | square, outlined | circle |
  | `sheet` | floating glass | numbered panel | docked with handle |
  | `pressFeedback` | scale | invert | morph to `pressedRadius` |
  | `separators` | none | hairline | none |

- **`motion`**: `enter`, `press`, `sheet`, `screen` and `idle`. Each entry is one of:
  - `{type: "timing", durationMs, easing: [x1,y1,x2,y2]}`
  - `{type: "spring", response, damping}`
  - `{type: "none"}`

  Springs map directly to SwiftUI `.spring(response:dampingFraction:)`. In Compose they
  map to `spring(dampingRatio = damping, stiffness = (2π / response)²)`. On the web they
  become a CSS `linear()` easing sampled from the spring.

## Haptic vocabulary

There are twelve semantic events. Components fire events and never raw patterns.

| Event | When | Glass | Swiss | Soft |
|---|---|---|---|---|
| `tap` | Generic button | light tap | click | soft pop |
| `send` | Message sent | soft tick | click | pop |
| `receive` | Message arrives in the open chat | glass tap | double click | bubble |
| `success` | File delivered, identity created, call connected | success swell | double click | boing |
| `verify` | Safety number confirmed | deep thunk | triple click | hug |
| `ring` | Incoming call, repeating | ring pulse | bell | wobble |
| `progressTick` | Every 10% of a hold-to-confirm, a little stronger each time | rising tick | click | rumble |
| `cancel` | Hold released early | release | click | deflate |
| `burned` | Identity destroyed | shatter | hard stop | poof |
| `sheetDetent` | Sheet opens or snaps | sheet detent | click | detent |
| `toggle` | Mute, camera, speaker, switches | toggle | click | squish |
| `hangup` | Call ends or is declined | hang up | double click | bye |

### Pattern format

A pattern is a list of `events`. Each event is
`{t (ms), kind: transient|continuous, intensity 0–1, sharpness 0–1, durationMs?}`, plus a
`web` fallback for `navigator.vibrate`. `scaleWithProgress` scales intensity by the hold
progress (on the web, each pulse lasts up to three times as long). Each platform maps events as follows:

| Platform | Mapping |
|---|---|
| iOS / macOS | `CHHapticEvent` `.hapticTransient` / `.hapticContinuous`, with intensity and sharpness passed directly. Generated as AHAP files. |
| Android 12+ | `VibrationEffect.Composition`. Transient events map to `PRIMITIVE_CLICK` when sharpness ≥ 0.6, `PRIMITIVE_TICK` when it's 0.3–0.6, and `PRIMITIVE_LOW_TICK` otherwise (`PRIMITIVE_THUD` when intensity ≥ 0.8 and sharpness < 0.3). Scale is the intensity; delays come from `t`. Continuous events become an amplitude waveform. Older devices fall back to the `EFFECT_*` predefined effects. |
| Web | The `web` duration array on Android browsers; on iOS Safari (18+), one `<input switch>` system tick per pulse (`appearance.ts`); nothing elsewhere. |
| Android app (Tauri) | `tauri-plugin-haptics`, pulse by pulse at `t` (`apps/web/src/app/haptics.ts`). A transient is an impact: `heavy` from intensity 0.8; from 0.5 `rigid` when sharpness ≥ 0.6, else `medium`; below, `light`, or `soft` when sharpness < 0.3. A continuous event vibrates for its `durationMs`. `toggle` and `progressTick` are selection feedback. |
| Linux app | None (no haptics hardware). |

### Haptic rules

- Respect the system haptics setting, plus an in-app toggle (Settings → Appearance →
  Haptics).
- Haptics always accompany a visual or audio change; they are never the only signal.
- Leave at least 30 ms between events. A hold fires at most 10 `progressTick`s.

## Hold to burn

The one hold-to-confirm (`Hold.tsx`). Holding for 2 s fills a bar across the button,
with a `progressTick` at every tenth, a little stronger each time; the label reads
"Keep holding". Letting go early plays `cancel` and the bar drains back. At the end,
`burned` plays and the app starts afresh. Nothing else moves: it is a progress bar,
not a spectacle.

## First launch

A four-page tour (`Tour.tsx`): no account, connecting by card, checking safety numbers,
keys only on your devices. Then the identity it made, with Continue, Link and Restore.
Skip goes straight there. Settings → How krypt works shows the tour again.
- No haptics for background activity. A message arriving in another chat is a
  notification's job.

## Choosing a theme

- **Default.** Everyone starts in Obsidian Glass. First launch shows no theme picker
  (decision 45); the theme is changed in Settings.
- **Settings → Appearance:**
  - Theme
  - Mode (System, Light, Dark; default System)
  - Accent (the current theme's four)
  - Haptics on/off
  - Reduce motion (follows the OS by default)
- **Switching** is instant, with no restart. Glass and Soft cross-fade over 200 ms; Swiss
  cuts.
- **Storage.** The choice is stored on the device. With a passkey account it syncs inside
  the encrypted multi-device state.
- **Reduced motion.** It collapses every theme to opacity-only transitions with no idle
  animation. Haptics are unaffected.

## Fonts

All fonts are SIL OFL: Geist, Geist Mono, Inter Tight, JetBrains Mono and Figtree. They
are **bundled with every client and self-hosted for the web**. The prototypes load Google
Fonts, but production must not, because fetching fonts from a third party leaks every
user's IP address and timing.
