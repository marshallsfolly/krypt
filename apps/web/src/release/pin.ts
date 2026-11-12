// The page's side of release pinning (docs/releases.md): it registers the
// service worker that runs only signed releases, shows which release is
// running, and warns when krypt.chat serves something else. A service
// worker that is replaced (the browser fetches it again at least daily) is
// checked here, by the page still running the signed code, against the
// signed release: a server that changes it is seen.

import { createSignal } from "solid-js";
import { fetchRelease, sha256 } from "./verify.js";

declare const __KRYPT_RELEASE_KEY__: string;

export type ReleaseState =
  /** A development build: no release key pinned. */
  | { state: "unpinned" }
  /** Pinned, and nothing verified yet (the first visit, while installing). */
  | { state: "checking" }
  | { state: "pinned"; release: string; commit: string }
  /** Something was refused; `release` is what still runs, if any. */
  | { state: "refused"; reason: string; release?: string; commit?: string };

const [release, setRelease] = createSignal<ReleaseState>(
  __KRYPT_RELEASE_KEY__ ? { state: "checking" } : { state: "unpinned" },
);
/** A newer signed release is in place: it runs from the next reload. */
const [updated, setUpdated] = createSignal(false);
export { release, updated };

/** Asks the service worker to look for a newer release now. */
export function checkRelease(force = false): void {
  navigator.serviceWorker?.controller?.postMessage({ type: "krypt-release-check", force });
}

type Message = { type?: string; state?: string; release?: string; commit?: string; reason?: string };

/** Set once this page has seen krypt.chat serve an unsigned service worker:
 * from then on nothing a service worker says clears the warning (a
 * replaced one would say all is well). */
let workerRefused = false;

function onMessage(data: Message) {
  if (data?.type !== "krypt-release" || workerRefused) return;
  if (data.state === "pinned" || data.state === "updated") {
    setRelease({ state: "pinned", release: data.release ?? "", commit: data.commit ?? "" });
    if (data.state === "updated") setUpdated(true);
  } else if (data.state === "refused") {
    setRelease({ state: "refused", reason: data.reason ?? "", release: data.release, commit: data.commit });
  } else if (data.state === "unpinned") {
    setRelease(__KRYPT_RELEASE_KEY__ ? { state: "checking" } : { state: "unpinned" });
  }
}

/** Whether the service worker krypt.chat now serves is the signed release's. */
async function signedWorker(): Promise<boolean> {
  try {
    const manifest = await fetchRelease(__KRYPT_RELEASE_KEY__);
    const served = new Uint8Array(await (await fetch("/sw.js", { cache: "no-store" })).arrayBuffer());
    return !!manifest && manifest.files["/sw.js"] === (await sha256(served));
  } catch {
    return false;
  }
}

/** Registers the service worker and follows what it says. */
export async function startPinning(): Promise<void> {
  if (!("serviceWorker" in navigator)) return;
  navigator.serviceWorker.addEventListener("message", (event) => onMessage(event.data as Message));
  const registration = await navigator.serviceWorker.register("/sw.js", { updateViaCache: "none" });
  if (!__KRYPT_RELEASE_KEY__) return;
  registration.addEventListener("updatefound", () => {
    void signedWorker().then((signed) => {
      if (!signed) {
        workerRefused = true;
        setRelease((now) => ({
          state: "refused",
          reason: "krypt.chat served a service worker that is not part of a signed release",
          ...((now.state === "pinned" || now.state === "refused") && { release: now.release, commit: now.commit }),
        }));
      }
    });
  });
  const ask = () => navigator.serviceWorker.controller?.postMessage({ type: "krypt-release-status" });
  navigator.serviceWorker.addEventListener("controllerchange", ask);
  ask();
}
