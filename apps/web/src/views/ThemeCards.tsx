import { For } from "solid-js";
import { appearance, haptic, themes } from "../app/appearance";

/** The three themes as live cards: each renders in its own tokens. */
export function ThemeCards() {
  return (
    <div class="theme-cards" role="radiogroup">
      <For each={themes}>
        {(theme) => (
          <button
            class="theme-card press"
            role="radio"
            aria-checked={appearance.theme().id === theme.id}
            data-theme={theme.id}
            data-mode={appearance.mode()}
            data-accent={theme.defaultAccent}
            onClick={() => {
              appearance.setTheme(theme.id);
              haptic("success", theme);
            }}
          >
            <span class="theme-sample">
              <span class="sample-bubble">Hey!</span>
              <span class="sample-bubble mine">Hi ✦</span>
            </span>
            <span class="headline">{theme.name}</span>
            <span class="caption muted">{theme.summary}</span>
          </button>
        )}
      </For>
    </div>
  );
}
