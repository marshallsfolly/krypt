import { onMount, Show } from "solid-js";
import { haptic } from "../app/appearance";
import { strings } from "../app/strings";
import { LegalLinks } from "./Legal";
import { Tour } from "./Tour";

/** First launch: how krypt works, then the identity it has just made. */
export function Onboarding(props: { fingerprint: string; onDone: () => void; onLink: () => void; onRestore?: () => void }) {
  onMount(() => haptic("success"));
  return (
    <main class="onboarding enter">
      <Tour
        end={
          <>
            <section class="stack">
              <h1 class="display">{strings.identityReady}</h1>
              <p class="body muted">{strings.identityHint}</p>
              <p class="fingerprint">{props.fingerprint}</p>
            </section>
            <div class="agree">
              <button class="btn wide" onClick={props.onDone}>
                {strings.continue}
              </button>
              <p class="caption muted">
                <LegalLinks words={strings.legal.agree} />
              </p>
            </div>
            <div class="row-actions">
              <button class="btn ghost" onClick={props.onLink}>
                {strings.devices.linkThis}
              </button>
              <Show when={props.onRestore}>
                {(onRestore) => (
                  <button class="btn ghost" onClick={onRestore()}>
                    {strings.passkeys.restore}
                  </button>
                )}
              </Show>
            </div>
          </>
        }
      />
    </main>
  );
}
