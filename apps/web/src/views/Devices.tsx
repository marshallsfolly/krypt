import { createResource, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { haptic } from "../app/appearance";
import { Icon } from "../app/icons";
import { mailboxBase } from "../app/platform";
import type { AppState } from "../app/state";
import { strings } from "../app/strings";
import { cardIdentity, isLinkCode, linkIdentity, LinkInvite } from "../core/krypt_wasm.js";
import { fingerprintOf } from "../runtime/device";
import { LinkCodeUsed, put, take } from "../runtime/link";
import {
  backup,
  claim,
  HandleTaken,
  handleState,
  NoHandle,
  normalize,
  PasskeyFailed,
  passkeysSupported,
  release,
  restore,
  type Restored,
} from "../runtime/passkey";
import { Qr } from "./Qr";
import { canScan, linkIn, Scanner } from "./Scanner";
import { Sheet } from "./Sheets";

/** A device's card, shortened to something a person can compare. */
const deviceLabel = (card: string) => {
  const inbox = card.slice(-8).toUpperCase();
  return `${strings.devices.device} ${inbox.slice(0, 4)} ${inbox.slice(4)}`;
};

/** On a new device: show a code for the identity's existing device to
 * scan, and wait for what it seals. `onLinked` gets the payload and a way
 * to answer once the new device exists. */
export function LinkThisDeviceSheet(props: {
  open: boolean;
  onClose: () => void;
  onLinked: (payload: Uint8Array, answer: (card: string) => Promise<void>) => Promise<void>;
}) {
  const [status, setStatus] = createSignal<string>(strings.devices.preparing);
  const [invite, setInvite] = createSignal<LinkInvite>();
  const [checking, setChecking] = createSignal<{ fingerprint: string; resolve: (ok: boolean) => void }>();
  const cancel = new AbortController();
  onCleanup(() => cancel.abort());
  onMount(async () => {
    try {
      // The key goes to its drop before the code is shown; a drop that is
      // somehow taken already means a new code.
      let ready: LinkInvite | undefined;
      for (let tries = 0; tries < 3 && !ready; tries++) {
        const candidate = new LinkInvite();
        try {
          await put(mailboxBase, candidate.keyDrop, candidate.publicKey as Uint8Array<ArrayBuffer>);
          ready = candidate;
        } catch {
          // Try another code.
        }
      }
      if (!ready) throw new Error("no key drop");
      setInvite(ready);
      setStatus(strings.devices.waiting);
      const sealed = await take(mailboxBase, ready.drop, cancel.signal);
      const payload = ready.open(sealed);
      // Whoever saw the code could have sealed their own identity first:
      // the person checks this is theirs before this device joins it.
      setStatus(strings.devices.check);
      const confirmed = await new Promise<boolean>((resolve) => setChecking({ fingerprint: fingerprintOf(linkIdentity(payload)), resolve }));
      setChecking(undefined);
      if (!confirmed) {
        haptic("cancel");
        setStatus(strings.devices.refused);
        return;
      }
      setStatus(strings.devices.linking);
      await props.onLinked(payload, (card) => put(mailboxBase, ready.replyDrop, ready.reply(card) as Uint8Array<ArrayBuffer>));
      haptic("success");
    } catch {
      if (!cancel.signal.aborted) setStatus(strings.devices.failed);
    }
  });
  return (
    <Sheet open={props.open} title={strings.devices.linkThis} onClose={props.onClose}>
      <div class="stack">
        <p class="body muted">{strings.devices.linkThisHint}</p>
        <Show when={invite()}>
          {(ready) => (
            <>
              <div class="qr-plate">
                <Qr text={ready().code} label={strings.devices.codeLabel} />
              </div>
              <code class="card-text" tabindex="0">
                {ready().code}
              </code>
            </>
          )}
        </Show>
        <p class="caption" role="status">
          {status()}
        </p>
        <Show when={checking()}>
          {(check) => (
            <>
              <p class="headline fingerprint">{check().fingerprint}</p>
              <div class="row-actions">
                <button class="btn ghost" onClick={() => check().resolve(false)}>
                  {strings.devices.differs}
                </button>
                <button class="btn" onClick={() => check().resolve(true)}>
                  {strings.devices.matches}
                </button>
              </div>
            </>
          )}
        </Show>
      </div>
    </Sheet>
  );
}

/** On an existing device: scan (or paste) a new device's code and link it. */
export function LinkNewDeviceSheet(props: { app: AppState; open: boolean; onClose: () => void }) {
  const [code, setCode] = createSignal("");
  const [scanning, setScanning] = createSignal(false);
  const [status, setStatus] = createSignal<string>();
  const [busy, setBusy] = createSignal(false);
  const cancel = new AbortController();
  onCleanup(() => cancel.abort());

  const link = async (text: string) => {
    if (!isLinkCode(text) || busy()) return;
    setBusy(true);
    setStatus(strings.devices.sending);
    try {
      await props.app.rt.linkNewDevice(text, cancel.signal);
      haptic("success");
      setStatus(strings.devices.linked);
      props.app.refreshDevices();
    } catch (error) {
      haptic("cancel");
      setStatus(
        error instanceof LinkCodeUsed
          ? strings.devices.codeUsed
          : String(error).includes("older krypt")
            ? strings.devices.codeOld
            : strings.devices.failed,
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={props.open} title={strings.devices.linkNew} onClose={props.onClose}>
      <div class="stack">
        <p class="body muted">{strings.devices.linkNewHint}</p>
        <p class="caption muted">{strings.devices.yourFingerprint}</p>
        <p class="headline fingerprint">{fingerprintOf(props.app.me)}</p>
        <Show when={scanning()}>
          <Scanner
            accept={linkIn}
            onCard={(found) => {
              setScanning(false);
              setCode(found);
              void link(found);
            }}
            onError={() => setScanning(false)}
          />
        </Show>
        <Show when={canScan() && !scanning() && !busy()}>
          <button type="button" class="btn ghost" onClick={() => setScanning(true)}>
            <Icon name="scan" size={18} />
            {strings.scan}
          </button>
        </Show>
        <label class="field">
          <span class="label">{strings.devices.codeLabel}</span>
          <textarea
            class="mono-input"
            rows="3"
            placeholder="krypt-link2:…"
            value={code()}
            onInput={(e) => setCode(e.currentTarget.value.trim())}
            autocomplete="off"
            spellcheck={false}
          />
        </label>
        <button class="btn wide" disabled={!isLinkCode(code()) || busy()} onClick={() => void link(code())}>
          {strings.devices.link}
        </button>
        <Show when={status()}>
          {(text) => (
            <p class="caption" role="status">
              {text()}
            </p>
          )}
        </Show>
        <p class="caption muted">{strings.devices.linkWarning}</p>
      </div>
    </Sheet>
  );
}

/** On a new device: open the backup kept with a handle, with its passkey. */
export function RestoreSheet(props: { open: boolean; onClose: () => void; onRestored: (restored: Restored) => Promise<void> }) {
  const [handle, setHandle] = createSignal("");
  const [status, setStatus] = createSignal<string>();
  const [busy, setBusy] = createSignal(false);
  const go = async (e: Event) => {
    e.preventDefault();
    if (!normalize(handle()) || busy()) return;
    setBusy(true);
    setStatus(undefined);
    try {
      const restored = await restore(mailboxBase, handle());
      setStatus(strings.passkeys.restoring);
      await props.onRestored(restored);
      haptic("success");
    } catch (error) {
      setStatus(error instanceof NoHandle ? strings.passkeys.noBackup : strings.passkeys.failed);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Sheet open={props.open} title={strings.passkeys.restore} onClose={props.onClose}>
      <form class="stack" onSubmit={go}>
        <p class="body muted">{strings.passkeys.restoreHint}</p>
        <label class="field">
          <span class="label">{strings.passkeys.handle}</span>
          <input
            class="body"
            placeholder="@name"
            value={handle()}
            onInput={(e) => setHandle(e.currentTarget.value)}
            autocomplete="username webauthn"
            autocapitalize="off"
            spellcheck={false}
          />
        </label>
        <button class="btn wide" type="submit" disabled={!normalize(handle()) || busy()}>
          {strings.passkeys.restoreButton}
        </button>
        <Show when={status()}>
          {(text) => (
            <p class="caption" role="status">
              {text()}
            </p>
          )}
        </Show>
      </form>
    </Sheet>
  );
}

/** Settings: this identity's other devices. */
export function DevicesSection(props: { app: AppState; onLinkNew: () => void }) {
  return (
    <>
      <p class="caption muted">{strings.devices.hint}</p>
      <ul class="list" role="list" aria-label={strings.devices.title}>
        <li class="member">
          <span class="list-text">
            <span class="headline">{strings.devices.thisOne}</span>
            <span class="meta muted">{deviceLabel(props.app.rt.contactCard)}</span>
          </span>
        </li>
        <For each={props.app.devices()}>
          {(card) => (
            <li class="member">
              <span class="list-text">
                <span class="headline">{deviceLabel(card)}</span>
                <span class="meta muted">{fingerprintOf(cardIdentity(card) ?? "")}</span>
              </span>
              <button
                class="chip press"
                onClick={() => {
                  haptic("toggle");
                  void props.app.rt.removeDevice(card).then(props.app.refreshDevices);
                }}
              >
                {strings.devices.unlink}
              </button>
            </li>
          )}
        </For>
      </ul>
      <button class="btn ghost" onClick={props.onLinkNew}>
        <Icon name="plus" size={18} />
        {strings.devices.linkNew}
      </button>
    </>
  );
}

/** Settings: the @handle, and the passkey backup that comes with it. */
export function HandleSection(props: { app: AppState }) {
  const [state, setState] = createSignal(handleState());
  const [wanted, setWanted] = createSignal("");
  const [status, setStatus] = createSignal<string>();
  const [busy, setBusy] = createSignal(false);
  const [supported] = createResource(async () => passkeysSupported());

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setStatus(undefined);
    try {
      await work();
    } finally {
      setBusy(false);
      setState(handleState());
    }
  };
  const claimIt = () =>
    run(async () => {
      try {
        await claim(props.app.rt, mailboxBase, wanted());
        haptic("success");
      } catch (error) {
        haptic("cancel");
        setStatus(
          error instanceof HandleTaken
            ? strings.passkeys.taken
            : error instanceof PasskeyFailed
              ? strings.passkeys.failed
              : strings.passkeys.claimFailed,
        );
      }
    });

  return (
    <Show when={supported()}>
      <Show
        when={state()}
        fallback={
          <form
            class="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void claimIt();
            }}
          >
            <p class="caption muted">{strings.passkeys.hint}</p>
            <label class="field">
              <span class="label">{strings.passkeys.handle}</span>
              <input
                class="body"
                placeholder="@name"
                value={wanted()}
                onInput={(e) => setWanted(e.currentTarget.value)}
                autocapitalize="off"
                spellcheck={false}
                maxLength={25}
              />
            </label>
            <button class="btn" type="submit" disabled={!normalize(wanted()) || busy()}>
              {strings.passkeys.claim}
            </button>
          </form>
        }
      >
        {(s) => (
          <div class="stack">
            <div class="setting">
              <span class="headline">@{s().name}</span>
              <span class="caption muted">
                {s().prf
                  ? s().backedUpAt
                    ? strings.passkeys.backedUp(new Date(s().backedUpAt!).toLocaleString())
                    : strings.passkeys.notBackedUp
                  : strings.passkeys.noPrf}
              </span>
            </div>
            <div class="row-actions">
              <Show when={s().prf}>
                <button
                  class="btn ghost"
                  disabled={busy()}
                  onClick={() =>
                    void run(async () => {
                      if (!(await backup(props.app.rt, mailboxBase))) setStatus(strings.passkeys.backupFailed);
                    })
                  }
                >
                  {strings.passkeys.backupNow}
                </button>
              </Show>
              <button
                class="btn ghost danger-text"
                disabled={busy()}
                onClick={() =>
                  void run(async () => {
                    try {
                      await release(mailboxBase);
                    } catch {
                      setStatus(strings.passkeys.failed);
                    }
                  })
                }
              >
                {strings.passkeys.release}
              </button>
            </div>
          </div>
        )}
      </Show>
      <Show when={status()}>
        {(text) => (
          <p class="caption" role="status">
            {text()}
          </p>
        )}
      </Show>
    </Show>
  );
}
