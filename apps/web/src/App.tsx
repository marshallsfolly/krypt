import { createEffect, createSignal, Match, on, onCleanup, onMount, Show, Switch } from "solid-js";
import { haptic } from "./app/appearance";
import { mailboxBase, native } from "./app/platform";
import { createAppState, type AppState } from "./app/state";
import { strings } from "./app/strings";
import { reconcilePush } from "./app/push";
import { linkApp } from "./core/krypt_wasm.js";
import { Runtime } from "./runtime/device";
import { finishRestore, keepBackedUp, passkeysSupported, type Restored } from "./runtime/passkey";
import { CallScreen } from "./views/Call";
import { Chat } from "./views/Chat";
import { LinkNewDeviceSheet, LinkThisDeviceSheet, RestoreSheet } from "./views/Devices";
import { Home } from "./views/Home";
import { Onboarding } from "./views/Onboarding";
import { Settings, type SettingsPage } from "./views/Settings";
import { checkRelease, release, updated as releaseUpdated } from "./release/pin";
import { InfoSheet, JoinSheet, MyCardSheet, NewChatSheet } from "./views/Sheets";

export type View = { name: "home" } | { name: "chat"; id: string; focus?: string } | { name: "settings"; page?: SettingsPage };

/** How far from the chat list a view is: each step is one press of back. */
const depth = (v: View) => (v.name === "home" ? 0 : v.name === "settings" && v.page ? 2 : 1);
export type SheetName = "newChat" | "myCard" | "info" | "linkThis" | "linkNew" | "restore" | "join" | undefined;

const ONBOARDED = "krypt.onboarded";
const UPDATE_CHECK_MS = 15 * 60_000;

function onboarded(): boolean {
  try {
    return localStorage.getItem(ONBOARDED) === "1";
  } catch {
    return true;
  }
}

/** A contact card arriving as a link: https://krypt.chat/#add=krypt:… The
 * fragment never reaches any server. */
function linkedCard(): string | undefined {
  const match = /^#add=(.+)$/.exec(location.hash);
  if (!match) return undefined;
  history.replaceState(null, "", location.pathname);
  try {
    return decodeURIComponent(match[1]!);
  } catch {
    // Not a link anyone made (a stray `%`): nothing to add.
    return undefined;
  }
}

/** A group's invite link: https://krypt.chat/#join=… (its code). */
function linkedJoin(): string | undefined {
  const match = /^#join=([a-z2-7]+)$/i.exec(location.hash);
  if (!match) return undefined;
  history.replaceState(null, "", location.pathname);
  return match[1];
}

export function App() {
  const [phase, setPhase] = createSignal<"starting" | "waiting" | "ready" | "fatal">("starting");
  const [app, setApp] = createSignal<AppState>();
  const [view, setView] = createSignal<View>({ name: "home" });
  const [sheet, setSheet] = createSignal<SheetName>();
  const [card, setCard] = createSignal(linkedCard());
  const [join, setJoin] = createSignal(linkedJoin());
  const [welcome, setWelcome] = createSignal(!onboarded());

  let stopBackups = () => {};
  onCleanup(() => stopBackups());

  // The app only changes when it reloads, so a tab left open keeps running
  // the version it started with. Check for a newer one when krypt comes back
  // to the front, and every so often, and offer to reload.
  const [updateReady, setUpdateReady] = createSignal(false);
  const running = /\/assets\/index-[\w-]+\.js/.exec(
    document.querySelector<HTMLScriptElement>('script[type="module"][src*="/assets/"]')?.src ?? "",
  )?.[0];
  const checkForUpdate = async () => {
    if (native || updateReady() || document.visibilityState !== "visible") return;
    // A signed release: its service worker fetches and checks the next one,
    // and says when it is ready (`updated`).
    if (release().state !== "unpinned") return checkRelease();
    if (!running) return;
    try {
      const page = await (await fetch("/", { cache: "no-store" })).text();
      const latest = /\/assets\/index-[\w-]+\.js/.exec(page)?.[0];
      if (latest && latest !== running) setUpdateReady(true);
    } catch {
      // Offline; try again later.
    }
  };
  const updateTimer = setInterval(() => void checkForUpdate(), UPDATE_CHECK_MS);
  document.addEventListener("visibilitychange", checkForUpdate);
  onCleanup(() => {
    clearInterval(updateTimer);
    document.removeEventListener("visibilitychange", checkForUpdate);
  });

  /** Starts the device: the stored one, a new one, or (`linked`) a new
   * device of an existing identity. */
  const start = async (linked?: Uint8Array) => {
    const rt = await Runtime.start(
      mailboxBase,
      () => setPhase("waiting"),
      () => setPhase("fatal"),
      linked,
    );
    setApp(await createAppState(rt));
    setPhase("ready");
    void reconcilePush(rt);
    stopBackups();
    stopBackups = keepBackedUp(rt, mailboxBase);
    return rt;
  };

  onMount(async () => {
    try {
      await start();
      if (card()) setSheet("newChat");
      else if (join()) setSheet("join");
    } catch (error) {
      console.error(error);
      setPhase("fatal");
    }
  });

  /** Replaces the fresh device made at first launch with one of an
   * existing identity (linked, or restored from a passkey). */
  const become = async (payload: Uint8Array, then: (rt: Runtime) => Promise<void>) => {
    const current = app();
    setPhase("starting");
    setSheet(undefined);
    await current?.rt.burn();
    const rt = await start(payload);
    await then(rt);
    finishWelcome();
  };

  // The system back button (and the browser's) closes the open sheet, else
  // goes back to the list. Opening a sheet or a screen adds a step back.
  let ignorePop = false;
  let popping = false;
  /** Where a history step back (`open` going up) lands. */
  let landing: View | undefined;
  createEffect(
    on(
      sheet,
      (now, before) => {
        if (now && !before) history.pushState({ krypt: "sheet" }, "");
        else if (!now && before && !popping && history.state?.krypt === "sheet") {
          ignorePop = true;
          history.back();
        }
      },
      { defer: true },
    ),
  );
  const onPop = () => {
    if (ignorePop) {
      ignorePop = false;
      return;
    }
    popping = true;
    const v = view();
    if (landing) setView(landing);
    else if (sheet()) setSheet(undefined);
    else if (v.name === "settings" && v.page) setView({ name: "settings" });
    else setView({ name: "home" });
    landing = undefined;
    popping = false;
  };
  window.addEventListener("popstate", onPop);
  onCleanup(() => window.removeEventListener("popstate", onPop));

  const open = (next: View) => {
    haptic("tap");
    const from = depth(view());
    const to = depth(next);
    if (to < from && history.state?.krypt) {
      landing = next;
      history.go(to - from);
      return;
    }
    if (to > from) history.pushState({ krypt: true }, "");
    else if (to > 0) history.replaceState({ krypt: true }, "");
    setView(next);
  };

  const finishWelcome = () => {
    try {
      localStorage.setItem(ONBOARDED, "1");
    } catch {
      // Shown again next time; harmless.
    }
    setWelcome(false);
  };

  return (
    <div class="app" data-view={view().name}>
      <div class="ambient" aria-hidden="true" />
      <Show when={release().state === "refused" && release()}>
        {(r) => (
          <p class="release-warning caption" role="alert">
            {strings.release.refused((r() as { release?: string }).release)}
          </p>
        )}
      </Show>
      <Show when={updateReady() || releaseUpdated()}>
        <button class="update-banner press label" onClick={() => location.reload()}>
          {strings.updateReady}
        </button>
      </Show>
      <Switch>
        <Match when={phase() === "starting"}>
          <div class="center">
            <div class="brand">{strings.appName}</div>
            <p class="muted">{strings.loading}</p>
          </div>
        </Match>
        <Match when={phase() === "waiting"}>
          <div class="center">
            <h1 class="title">{strings.otherTab}</h1>
            <p class="muted narrow">{strings.otherTabHint}</p>
          </div>
        </Match>
        <Match when={phase() === "fatal"}>
          <div class="center">
            <h1 class="title">{strings.fatal}</h1>
            <p class="muted narrow">{strings.fatalHint}</p>
            <button class="btn" onClick={() => location.reload()}>
              {strings.reload}
            </button>
          </div>
        </Match>
        <Match when={phase() === "ready" && app()}>
          {(state) => (
            <Show
              when={!welcome()}
              fallback={
                <>
                  <Onboarding
                    fingerprint={state().rt.fingerprint}
                    onDone={finishWelcome}
                    onLink={() => setSheet("linkThis")}
                    onRestore={passkeysSupported() ? () => setSheet("restore") : undefined}
                  />
                  <Show when={sheet() === "linkThis"}>
                    <LinkThisDeviceSheet
                      open
                      onClose={() => setSheet(undefined)}
                      onLinked={(payload, answer) =>
                        become(payload, async (rt) => {
                          await answer(rt.contactCard);
                          await rt.importApp(linkApp(payload));
                        })
                      }
                    />
                  </Show>
                  <RestoreSheet
                    open={sheet() === "restore"}
                    onClose={() => setSheet(undefined)}
                    onRestored={(restored: Restored) => become(restored.payload, (rt) => finishRestore(rt, mailboxBase, restored))}
                  />
                </>
              }
            >
              <div class="panes">
                <Home
                  app={state()}
                  current={view().name === "chat" ? (view() as { id: string }).id : undefined}
                  onOpen={(id, focus) => open({ name: "chat", id, focus })}
                  onSheet={(s) => {
                    haptic("sheetDetent");
                    setSheet(s);
                  }}
                  onSettings={() => open({ name: "settings" })}
                />
                <Switch fallback={<div class="pane pane-empty" />}>
                  <Match when={view().name === "chat" && (view() as { id: string }).id}>
                    {(id) => (
                      <Chat
                        app={state()}
                        id={id()}
                        focus={(view() as { focus?: string }).focus}
                        onBack={() => open({ name: "home" })}
                        onInfo={() => {
                          haptic("sheetDetent");
                          setSheet("info");
                        }}
                      />
                    )}
                  </Match>
                  <Match when={view().name === "settings"}>
                    <Settings
                      app={state()}
                      page={(view() as { page?: SettingsPage }).page}
                      onOpen={(page) => open({ name: "settings", page })}
                      onBack={() => {
                        const page = (view() as { page?: SettingsPage }).page;
                        open(page ? { name: "settings" } : { name: "home" });
                      }}
                      onLinkNew={() => {
                        haptic("sheetDetent");
                        setSheet("linkNew");
                      }}
                    />
                  </Match>
                </Switch>
              </div>
              <NewChatSheet
                app={state()}
                open={sheet() === "newChat"}
                initial={card()}
                onClose={() => {
                  setCard(undefined);
                  setSheet(undefined);
                }}
                onStarted={(id) => {
                  // The sheet's step back becomes the chat's.
                  history.replaceState({ krypt: "chat" }, "");
                  setCard(undefined);
                  setSheet(undefined);
                  setView({ name: "chat", id });
                }}
              />
              <MyCardSheet app={state()} open={sheet() === "myCard"} onClose={() => setSheet(undefined)} />
              <Show when={sheet() === "join" && join()}>
                {(code) => (
                  <JoinSheet
                    app={state()}
                    code={code()}
                    open
                    onClose={() => {
                      setJoin(undefined);
                      setSheet(undefined);
                    }}
                  />
                )}
              </Show>
              <Show when={sheet() === "linkNew"}>
                <LinkNewDeviceSheet app={state()} open onClose={() => setSheet(undefined)} />
              </Show>
              <CallScreen app={state()} calls={state().calls} />
              <Show when={view().name === "chat" && (view() as { id: string }).id}>
                {(id) => (
                  <InfoSheet
                    app={state()}
                    id={id()}
                    open={sheet() === "info"}
                    onClose={() => setSheet(undefined)}
                    onGone={() => {
                      history.replaceState({ krypt: "gone" }, "");
                      setSheet(undefined);
                      setView({ name: "home" });
                    }}
                  />
                )}
              </Show>
            </Show>
          )}
        </Match>
      </Switch>
    </div>
  );
}
