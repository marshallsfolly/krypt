// Typing and online status, shown only to people this device is connected
// with (accepted conversations; never message requests or blocked people).
//
// Signals travel encrypted over the conversations' open sockets and are
// stored nowhere (decision 47): someone offline never sees an old "typing",
// and nothing piles up. So each one is shown for a while and renewed by the
// next, and a device that just opened asks who else is online ("hello").
// Both are on by default and each can be turned off in Settings → Privacy;
// as in other messengers, turning one off also stops showing it from others.

import { createEffect, createRoot, createSignal } from "solid-js";
import { createStore, produce, reconcile } from "solid-js/store";
import type { ConversationInfo, SignalKind } from "../core/krypt_wasm.js";
import type { Runtime } from "../runtime/device";

/** While typing, say so again this often. */
const TYPING_AGAIN_MS = 3_000;
/** No keystroke this long: stopped. */
const TYPING_PAUSE_MS = 5_000;
/** "Typing" shows this long unless renewed (a lost "stopped" ends here). */
const TYPING_SHOWN_MS = 7_000;
/** While krypt is open and on screen, say so this often. */
const ONLINE_AGAIN_MS = 45_000;
/** "Online" shows this long unless renewed: a closed tab may say nothing. */
const ONLINE_SHOWN_MS = 100_000;
/** Answer someone's "hello" at most this often per conversation. */
const ANSWER_EVERY_MS = 10_000;
/** Online status goes to this many of the most recent conversations. */
const PRESENCE_CONVERSATIONS_MAX = 32;

const TYPING_KEY = "krypt.typing";
const ONLINE_KEY = "krypt.online";

function setting(key: string): boolean {
  try {
    return localStorage.getItem(key) !== "0";
  } catch {
    return true;
  }
}

function save(key: string, on: boolean) {
  try {
    localStorage.setItem(key, on ? "1" : "0");
  } catch {
    // Back to the default next time.
  }
}

export function createPresence(
  rt: Runtime,
  /** Conversations this device is connected with, most recent first. */
  connected: () => ConversationInfo[],
) {
  const [typingOn, setTypingOn] = createSignal(setting(TYPING_KEY));
  const [onlineOn, setOnlineOn] = createSignal(setting(ONLINE_KEY));
  /** conversation → identity → shown until. */
  const [typing, setTyping] = createStore<Record<string, Record<string, number>>>({});
  /** identity → device → shown until. */
  const [online, setOnline] = createStore<Record<string, Record<string, number>>>({});
  const [now, setNow] = createSignal(Date.now());
  // Lives as long as the page, like the device.
  setInterval(() => setNow(Date.now()), 1_000);

  const eligible = (id: string) => connected().some((c) => c.id === id);
  const visible = () => document.visibilityState === "visible";

  // ---- Sending --------------------------------------------------------------

  const typedAt = new Map<string, number>();
  const pauses = new Map<string, ReturnType<typeof setTimeout>>();

  const stopTyping = (conversation: string) => {
    clearTimeout(pauses.get(conversation));
    pauses.delete(conversation);
    if (!typedAt.delete(conversation)) return;
    rt.signal(conversation, "idle");
  };

  /** A keystroke in a conversation's composer. */
  const typed = (conversation: string) => {
    if (!typingOn() || !eligible(conversation)) return;
    const at = Date.now();
    if (at - (typedAt.get(conversation) ?? 0) >= TYPING_AGAIN_MS) {
      typedAt.set(conversation, at);
      rt.signal(conversation, "typing");
    }
    clearTimeout(pauses.get(conversation));
    pauses.set(
      conversation,
      setTimeout(() => stopTyping(conversation), TYPING_PAUSE_MS),
    );
  };

  const presence = () => connected().slice(0, PRESENCE_CONVERSATIONS_MAX);
  const answered = new Map<string, number>();

  const announce = (kind: SignalKind) => {
    if (!onlineOn()) return;
    for (const c of presence()) rt.signal(c.id, kind);
  };

  let beat: ReturnType<typeof setInterval> | undefined;
  const cameOnline = () => {
    if (!visible()) return;
    announce("hello");
    clearInterval(beat);
    beat = setInterval(() => announce("online"), ONLINE_AGAIN_MS);
  };
  const wentOffline = () => {
    clearInterval(beat);
    beat = undefined;
    for (const conversation of [...typedAt.keys()]) stopTyping(conversation);
    announce("offline");
  };
  const onVisibility = () => (visible() ? cameOnline() : wentOffline());
  document.addEventListener("visibilitychange", onVisibility);
  window.addEventListener("pagehide", wentOffline);
  // Sockets open a moment after start, and reopen after a drop: say hello
  // once they are up (signals sent while a socket is down are lost).
  let greet: ReturnType<typeof setTimeout> | undefined;
  rt.onConnected(() => {
    clearTimeout(greet);
    greet = setTimeout(() => beat !== undefined && announce("hello"), 500);
  });
  cameOnline();
  // A conversation just accepted or started: say hello there too, rather
  // than leave it to the next beat.
  createRoot(() => {
    let known = new Set<string>();
    createEffect(() => {
      const ids = presence().map((c) => c.id);
      const fresh = ids.filter((id) => !known.has(id));
      known = new Set(ids);
      if (beat !== undefined && onlineOn()) for (const id of fresh) rt.signal(id, "hello");
    });
  });

  // ---- Receiving ------------------------------------------------------------

  const clearTyping = (conversation: string, identity: string) =>
    setTyping(
      produce((t) => {
        if (t[conversation]) delete t[conversation][identity];
      }),
    );

  rt.onSignal((conversation, from, device, kind) => {
    if (from === rt.identity || !eligible(conversation)) return;
    const at = Date.now();
    if (kind === "offline") {
      setOnline(produce((o) => void (o[from] && delete o[from][device])));
      clearTyping(conversation, from);
      return;
    }
    if (kind === "idle") return clearTyping(conversation, from);
    if (onlineOn()) setOnline(from, (devices) => ({ ...devices, [device]: at + ONLINE_SHOWN_MS }));
    if (kind === "typing" && typingOn()) setTyping(conversation, (people) => ({ ...people, [from]: at + TYPING_SHOWN_MS }));
    // Someone just opened krypt: tell them this device is here too.
    if (kind === "hello" && onlineOn() && visible() && at - (answered.get(conversation) ?? 0) >= ANSWER_EVERY_MS) {
      answered.set(conversation, at);
      rt.signal(conversation, "online");
    }
  });

  return {
    typed,
    stopTyping,
    /** A message from them ends their typing there. */
    spoke: clearTyping,
    /** Who is typing in a conversation now. */
    typingIn: (conversation: string): string[] =>
      typingOn() ? Object.entries(typing[conversation] ?? {}).filter(([, until]) => until > now()).map(([identity]) => identity) : [],
    isOnline: (identity: string): boolean =>
      onlineOn() && Object.values(online[identity] ?? {}).some((until) => until > now()),
    typingOn,
    onlineOn,
    setTypingOn(on: boolean) {
      if (!on) for (const conversation of [...typedAt.keys()]) stopTyping(conversation);
      setTypingOn(on);
      save(TYPING_KEY, on);
      if (!on) setTyping(reconcile({}));
    },
    setOnlineOn(on: boolean) {
      if (!on) announce("offline");
      setOnlineOn(on);
      save(ONLINE_KEY, on);
      if (on) cameOnline();
      else setOnline(reconcile({}));
    },
  };
}

export type Presence = ReturnType<typeof createPresence>;
