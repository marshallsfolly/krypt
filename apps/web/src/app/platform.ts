// Where the client runs: a browser tab at krypt.chat, or the apps (Tauri,
// apps/native), whose page is served from inside the app (tauri://localhost
// on Linux, http://tauri.localhost on Android). The apps reach the mailbox
// and share links at krypt.chat instead of at their own origin.

const KRYPT = "https://krypt.chat";

/** Inside the Android or Linux app (Tauri injects this before any script). */
export const native = "__TAURI_INTERNALS__" in window;

/** The Android app, where haptics are native (./haptics.ts). */
export const android = native && /\bAndroid\b/.test(navigator.userAgent);

/** The mailbox (`/v1/…`): this page's own origin on the web. A build may
 * point the apps elsewhere (VITE_KRYPT_MAILBOX, e.g. a local edge). */
export const mailboxBase: string = native
  ? (import.meta.env.VITE_KRYPT_MAILBOX as string | undefined) || KRYPT
  : location.origin;

/** Where links to krypt open (contact cards: `<origin>/#add=…`). */
export const webOrigin: string = native ? KRYPT : location.origin;
