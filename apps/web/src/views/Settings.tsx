import { createResource, createSignal, For, Match, Show, Switch } from "solid-js";
import { appearance, haptic, type Mode } from "../app/appearance";
import { Icon } from "../app/icons";
import { native } from "../app/platform";
import { disablePush, enablePush, pushState, type PushState } from "../app/push";
import type { AppState } from "../app/state";
import { strings } from "../app/strings";
import { fingerprintOf } from "../runtime/device";
import { handleState, passkeysSupported } from "../runtime/passkey";
import { DevicesSection, HandleSection } from "./Devices";
import { Hold } from "./Hold";
import { ThemeCards } from "./ThemeCards";
import { Tour } from "./Tour";
import { release } from "../release/pin";

/** Settings is a short menu, most important first; each entry is a page. */
export type SettingsPage = "account" | "devices" | "privacy" | "notifications" | "appearance" | "guide" | "burn";

const modes: [Mode, string][] = [
  ["system", strings.modeSystem],
  ["light", strings.modeLight],
  ["dark", strings.modeDark],
];

function Notifications(props: { app: AppState; state?: PushState; onChange: (state: PushState) => void }) {
  const [busy, setBusy] = createSignal(false);
  const hint = () =>
    ({
      on: strings.notifyOn,
      off: strings.notifyOn,
      install: strings.notifyInstall,
      denied: strings.notifyDenied,
      unsupported: strings.notifyUnsupported,
    })[props.state ?? "off"];

  const toggle = async (on: boolean) => {
    setBusy(true);
    try {
      props.onChange(await (on ? enablePush(props.app.rt) : disablePush(props.app.rt)));
      haptic("toggle");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <label class="setting">
        <span class="body">{strings.notify}</span>
        <input
          type="checkbox"
          role="switch"
          class="switch"
          checked={props.state === "on"}
          disabled={busy() || !(props.state === "on" || props.state === "off")}
          onChange={(e) => void toggle(e.currentTarget.checked)}
        />
      </label>
      <Show when={props.state}>
        <p class="caption muted">{hint()}</p>
      </Show>
    </>
  );
}

function Appearance() {
  return (
    <>
      <ThemeCards />
      <div class="setting">
        <span class="body">{strings.mode}</span>
        <div class="segmented" role="radiogroup" aria-label={strings.mode}>
          <For each={modes}>
            {([mode, label]) => (
              <button
                role="radio"
                aria-checked={appearance.savedMode() === mode}
                onClick={() => {
                  haptic("toggle");
                  appearance.setMode(mode);
                }}
              >
                {label}
              </button>
            )}
          </For>
        </div>
      </div>
      <div class="setting">
        <span class="body">{strings.accent}</span>
        <div class="swatches" role="radiogroup" aria-label={strings.accent}>
          <For each={appearance.theme().accents}>
            {(accent) => (
              <button
                class="swatch press"
                role="radio"
                aria-label={accent.id}
                aria-checked={appearance.accent() === accent.id}
                style={{ "--swatch": accent.value }}
                onClick={() => {
                  haptic("toggle");
                  appearance.setAccent(accent.id);
                }}
              />
            )}
          </For>
        </div>
      </div>
      <label class="setting">
        <span class="body">{strings.haptics}</span>
        <input
          type="checkbox"
          role="switch"
          class="switch"
          checked={appearance.haptics()}
          onChange={(e) => {
            appearance.setHaptics(e.currentTarget.checked);
            haptic("toggle");
          }}
        />
      </label>
    </>
  );
}

function Privacy(props: { app: AppState }) {
  return (
    <>
      <label class="setting">
        <span class="body">{strings.calls.relay}</span>
        <input
          type="checkbox"
          role="switch"
          class="switch"
          checked={props.app.relayCalls()}
          onChange={(e) => {
            props.app.setRelayCalls(e.currentTarget.checked);
            haptic("toggle");
          }}
        />
      </label>
      <p class="caption muted">{strings.calls.relayHint}</p>
      <label class="setting">
        <span class="body">{strings.presence.typingSetting}</span>
        <input
          type="checkbox"
          role="switch"
          class="switch"
          checked={props.app.presence.typingOn()}
          onChange={(e) => {
            props.app.presence.setTypingOn(e.currentTarget.checked);
            haptic("toggle");
          }}
        />
      </label>
      <p class="caption muted">{strings.presence.typingHint}</p>
      <label class="setting">
        <span class="body">{strings.presence.onlineSetting}</span>
        <input
          type="checkbox"
          role="switch"
          class="switch"
          checked={props.app.presence.onlineOn()}
          onChange={(e) => {
            props.app.presence.setOnlineOn(e.currentTarget.checked);
            haptic("toggle");
          }}
        />
      </label>
      <p class="caption muted">{strings.presence.onlineHint}</p>
      <label class="setting">
        <span class="body">{strings.messages.receipts}</span>
        <input
          type="checkbox"
          role="switch"
          class="switch"
          checked={props.app.receipts.on()}
          onChange={(e) => {
            props.app.receipts.setOn(e.currentTarget.checked);
            haptic("toggle");
          }}
        />
      </label>
      <p class="caption muted">{strings.messages.receiptsHint}</p>
      <h2 class="label">{strings.safety.blocked}</h2>
      <Show when={props.app.blocked().length > 0} fallback={<p class="caption muted">{strings.safety.noBlocked}</p>}>
        <ul class="list" role="list" aria-label={strings.safety.blocked}>
          <For each={props.app.blocked()}>
            {(identity) => (
              <li class="member">
                <span class="list-text">
                  <span class="headline">{props.app.name(identity)}</span>
                  <span class="meta muted">{fingerprintOf(identity)}</span>
                </span>
                <button
                  class="chip press"
                  onClick={() => {
                    haptic("toggle");
                    void props.app.unblock(identity);
                  }}
                >
                  {strings.safety.unblock}
                </button>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </>
  );
}

function Burn(props: { app: AppState }) {
  const burn = async () => {
    await props.app.rt.burn();
    try {
      localStorage.clear();
    } catch {
      // Nothing stored there anyway.
    }
    location.reload();
  };
  return (
    <div class="burn stack">
      <p class="body">{strings.burnHint}</p>
      <Show when={!handleState()?.prf}>
        <p class="caption danger">{strings.settingsMenu.burnNoBackup}</p>
      </Show>
      <Hold label={strings.burnHold} holding={strings.burnKeep} onConfirm={() => void burn()}>
        <Icon name="flame" size={18} />
      </Hold>
    </div>
  );
}

/** Which release this is: signed (and which), a development build, or
 * what was refused. */
function ReleaseLine() {
  const text = () => {
    const r = release();
    switch (r.state) {
      case "unpinned":
        return strings.release.development;
      case "checking":
        return strings.release.checking;
      case "pinned":
        return strings.release.signed(r.release, r.commit);
      case "refused":
        return `${strings.release.refused(r.release)} ${r.reason}`;
    }
  };
  return (
    <p class="caption settings-release" classList={{ muted: release().state !== "refused", danger: release().state === "refused" }}>
      {text()}
    </p>
  );
}

/** One entry of the menu: what it is, and how it stands. */
function Entry(props: { icon: Parameters<typeof Icon>[0]["name"]; title: string; summary?: string; warn?: boolean; danger?: boolean; onClick: () => void }) {
  return (
    <li>
      <button class="list-item press setting-entry" classList={{ danger: props.danger }} onClick={props.onClick}>
        <span class="setting-icon" aria-hidden="true">
          <Icon name={props.icon} size={20} />
        </span>
        <span class="list-text">
          <span class="headline">{props.title}</span>
          <Show when={props.summary}>
            <span class="caption truncate" classList={{ muted: !props.warn, danger: props.warn }}>
              {props.summary}
            </span>
          </Show>
        </span>
        <Icon name="next" size={18} />
      </button>
    </li>
  );
}

function Menu(props: { app: AppState; push?: PushState; onOpen: (page: SettingsPage) => void }) {
  const handle = handleState();
  const account = () =>
    !handle
      ? strings.settingsMenu.noHandle
      : handle.prf
        ? strings.settingsMenu.handleBackedUp(handle.name)
        : strings.settingsMenu.handleOnly(handle.name);
  const devices = () => props.app.devices().length;
  const blocked = () => props.app.blocked().length;
  return (
    <>
      <div class="settings-me">
        <span class="label">{strings.fingerprint}</span>
        <span class="fingerprint small">{props.app.rt.fingerprint}</span>
        <Show when={handle}>{(h) => <span class="headline">@{h().name}</span>}</Show>
      </div>
      <ul class="list settings-menu" role="list">
        <Entry
          icon="shield"
          title={strings.settingsMenu.account}
          summary={passkeysSupported() || handle ? account() : strings.settingsMenu.noPasskeys}
          warn={!handle?.prf && passkeysSupported()}
          onClick={() => props.onOpen("account")}
        />
        <Entry
          icon="devices"
          title={strings.devices.title}
          summary={devices() === 0 ? strings.settingsMenu.oneDevice : strings.settingsMenu.devices(devices() + 1)}
          onClick={() => props.onOpen("devices")}
        />
        <Entry
          icon="lock"
          title={strings.settingsMenu.privacy}
          summary={strings.settingsMenu.privacySummary(props.app.relayCalls(), blocked())}
          onClick={() => props.onOpen("privacy")}
        />
        <Show when={!native}>
          <Entry
            icon="bell"
            title={strings.notifications}
            summary={strings.settingsMenu.push[props.push ?? "off"]}
            onClick={() => props.onOpen("notifications")}
          />
        </Show>
        <Entry
          icon="palette"
          title={strings.appearance}
          summary={appearance.theme().name}
          onClick={() => props.onOpen("appearance")}
        />
        <Entry icon="info" title={strings.settingsMenu.titles.guide} onClick={() => props.onOpen("guide")} />
      </ul>
      <ul class="list settings-menu" role="list">
        <Entry icon="flame" title={strings.burn} danger onClick={() => props.onOpen("burn")} />
      </ul>
      <ReleaseLine />
    </>
  );
}

export function Settings(props: {
  app: AppState;
  page?: SettingsPage;
  onOpen: (page: SettingsPage) => void;
  onBack: () => void;
  onLinkNew: () => void;
}) {
  const [initialPush] = createResource(pushState);
  const [changedPush, setPush] = createSignal<PushState>();
  const push = () => changedPush() ?? initialPush();
  const title = () => (props.page ? strings.settingsMenu.titles[props.page] : strings.settings);

  return (
    <section class="pane pane-settings" aria-label={title()}>
      <header class="bar">
        <button class="icon-btn back" onClick={props.onBack} aria-label={strings.back}>
          <Icon name="back" />
        </button>
        <h1 class="title">{title()}</h1>
      </header>
      <div class="scroll stack settings" data-page={props.page ?? "menu"}>
        <Switch fallback={<Menu app={props.app} push={push()} onOpen={props.onOpen} />}>
          <Match when={props.page === "account"}>
            <Show when={passkeysSupported() || handleState()} fallback={<p class="body muted">{strings.settingsMenu.noPasskeys}</p>}>
              <HandleSection app={props.app} />
            </Show>
            <div class="setting">
              <span class="body">{strings.fingerprint}</span>
              <span class="fingerprint small">{props.app.rt.fingerprint}</span>
            </div>
          </Match>
          <Match when={props.page === "devices"}>
            <DevicesSection app={props.app} onLinkNew={props.onLinkNew} />
          </Match>
          <Match when={props.page === "privacy"}>
            <Privacy app={props.app} />
          </Match>
          <Match when={props.page === "notifications"}>
            <Notifications app={props.app} state={push()} onChange={setPush} />
          </Match>
          <Match when={props.page === "appearance"}>
            <Appearance />
          </Match>
          <Match when={props.page === "guide"}>
            <Tour
              end={
                <section class="stack">
                  <h1 class="display">{strings.tour.done}</h1>
                  <p class="body muted">{strings.tour.doneHint}</p>
                  <button class="btn wide" onClick={props.onBack}>
                    {strings.tour.close}
                  </button>
                </section>
              }
            />
          </Match>
          <Match when={props.page === "burn"}>
            <Burn app={props.app} />
          </Match>
        </Switch>
      </div>
    </section>
  );
}
