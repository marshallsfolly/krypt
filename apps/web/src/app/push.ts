// Notifications while krypt is closed: a Web Push subscription whose
// endpoint the mailbox wakes. Wakeups carry nothing; the service worker
// shows a content-free notification and the app fetches when opened.

import type { Runtime } from "../runtime/device";
import { native } from "./platform";
import { VAPID_PUBLIC_KEY } from "./push-key";

export type PushState = "unsupported" | "install" | "denied" | "off" | "on";

function key(): Uint8Array<ArrayBuffer> {
  const base64 = VAPID_PUBLIC_KEY.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

/** Web Push needs a browser: the apps' webviews have no push service, and
 * their native push (FCM, APNs) needs accounts krypt does not have yet. */
function supported(): boolean {
  return !native && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

async function registration(): Promise<ServiceWorkerRegistration | undefined> {
  if (!("serviceWorker" in navigator)) return undefined;
  return (await navigator.serviceWorker.getRegistration("/")) ?? navigator.serviceWorker.register("/sw.js");
}

export async function pushState(): Promise<PushState> {
  if (!supported()) {
    // iPhone and iPad offer Web Push only to apps on the Home Screen.
    return /iPhone|iPad|iPod/.test(navigator.userAgent) ? "install" : "unsupported";
  }
  if (Notification.permission === "denied") return "denied";
  const subscription = await (await registration())?.pushManager.getSubscription();
  return subscription ? "on" : "off";
}

export async function enablePush(rt: Runtime): Promise<PushState> {
  const permission = await Notification.requestPermission();
  if (permission !== "granted") return permission === "denied" ? "denied" : "off";
  const reg = await registration();
  if (!reg) return "unsupported";
  await navigator.serviceWorker.ready;
  const subscription =
    (await reg.pushManager.getSubscription()) ??
    (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key() }));
  await rt.setPushTarget(subscription.endpoint);
  return "on";
}

export async function disablePush(rt: Runtime): Promise<PushState> {
  const subscription = await (await registration())?.pushManager.getSubscription();
  await subscription?.unsubscribe();
  await rt.setPushTarget(null);
  return "off";
}

/** On start: the service worker is in place, and the mailbox wakes this
 * browser's current subscription (which the browser may have rotated, or
 * the user revoked, while krypt was closed). */
export async function reconcilePush(rt: Runtime): Promise<void> {
  if (!supported()) return;
  const reg = await registration().catch(() => undefined);
  const subscription = await reg?.pushManager.getSubscription().catch(() => null);
  const endpoint = Notification.permission === "granted" ? (subscription?.endpoint ?? null) : null;
  if (endpoint !== (rt.pushTarget ?? null)) await rt.setPushTarget(endpoint);
}
