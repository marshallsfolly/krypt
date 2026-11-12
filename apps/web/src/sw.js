// krypt's service worker (docs/releases.md). Built into dist/sw.js with
// release/verify.js inlined and the release key pinned (vite.config.ts).
//
// It runs only signed releases: on install, and whenever the app is
// opened, it fetches the release's manifest, checks its signature against
// the pinned key, fetches every file it lists and checks each one's hash,
// and only then serves the app from that copy. A newer signed release
// replaces it; anything else (unsigned, tampered with, older) is refused,
// the app keeps running the release it has, and its pages are told why.
// A development build has no key pinned and is served as it is.
//
// It also turns a push into a notification. It never sees a message:
// wakeups carry no payload, and the app fetches and decrypts when it opens.
// The words here are fixed for the same reason.

/*__KRYPT_VERIFY__*/

const RELEASE_KEY = "__KRYPT_RELEASE_KEY__";
/** The release's own security headers (public/_headers, at build time):
 * set here on what it serves, whatever the server sent with it. */
const HEADERS = "__KRYPT_HEADERS__";
/** Types by extension, likewise not taken from the server. */
const TYPES = {
  html: "text/html; charset=utf-8",
  js: "text/javascript",
  css: "text/css",
  wasm: "application/wasm",
  json: "application/json",
  webmanifest: "application/manifest+json",
  png: "image/png",
  svg: "image/svg+xml",
  ico: "image/x-icon",
  woff2: "font/woff2",
  woff: "font/woff",
  txt: "text/plain; charset=utf-8",
};
const PIN = "krypt-pin";
const STATE = "/__krypt/release";
/** Looking for a newer release at most this often. */
const CHECK_MS = 60_000;

let lastCheck = 0;
let checking;
/** Why the last release was refused, for pages that ask. */
let problem;

async function current() {
  const hit = await (await caches.open(PIN)).match(STATE);
  return hit ? hit.json() : undefined;
}

/** Fetches every file of `manifest`, checks each against it, keeps them. */
async function stage(manifest) {
  const name = `krypt-${manifest.release}`;
  await caches.delete(name);
  const cache = await caches.open(name);
  for (const [path, hash] of Object.entries(manifest.files)) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`${path} could not be fetched (${response.status})`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if ((await sha256(bytes)) !== hash) throw new Error(`${path} is not the file the release signed`);
    const extension = path.slice(path.lastIndexOf(".") + 1);
    const headers = new Headers(HEADERS);
    headers.set("content-type", TYPES[extension] ?? "application/octet-stream");
    await cache.put(path, new Response(bytes, { headers }));
  }
  return name;
}

async function tell(message) {
  for (const client of await self.clients.matchAll({ type: "window", includeUncontrolled: true })) {
    client.postMessage({ type: "krypt-release", ...message });
  }
}

/** Takes a newer signed release if there is one; refuses anything else. */
function check(force) {
  if (!RELEASE_KEY) return Promise.resolve();
  if (!force && Date.now() - lastCheck < CHECK_MS) return checking ?? Promise.resolve();
  lastCheck = Date.now();
  checking ??= (async () => {
    const running = await current();
    const refuse = async (reason) => {
      problem = reason;
      await tell({ state: "refused", reason, release: running?.release });
    };
    let manifest;
    try {
      manifest = await fetchRelease(RELEASE_KEY);
    } catch (error) {
      return refuse(error instanceof Error ? error.message : String(error));
    }
    if (!manifest) {
      if (running) await refuse("krypt.chat served no signed release");
      return;
    }
    if (running) {
      const order = compareReleases(manifest.release, running.release);
      if (order < 0) return refuse(`krypt.chat served an older release (${manifest.release})`);
      if (order === 0) return;
    }
    try {
      const cache = await stage(manifest);
      const state = { release: manifest.release, commit: manifest.commit, cache, files: manifest.files };
      await (await caches.open(PIN)).put(STATE, new Response(JSON.stringify(state)));
      for (const name of await caches.keys()) {
        if (name !== PIN && name !== cache) await caches.delete(name);
      }
      problem = undefined;
      await tell({ state: running ? "updated" : "pinned", release: manifest.release, commit: manifest.commit });
    } catch (error) {
      await caches.delete(`krypt-${manifest.release}`);
      return refuse(error instanceof Error ? error.message : String(error));
    }
  })().finally(() => {
    checking = undefined;
  });
  return checking;
}

self.addEventListener("install", (event) => {
  event.waitUntil(check(true).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (!RELEASE_KEY || request.method !== "GET" || url.origin !== self.location.origin) return;
  // The mailbox and the release itself always come from the network.
  if (url.pathname.startsWith("/v1/") || url.pathname.startsWith("/release/")) return;
  event.respondWith(
    (async () => {
      const running = await current();
      // Nothing pinned yet (the first visit, before install finished).
      if (!running) return fetch(request);
      if (request.mode === "navigate") event.waitUntil(check(false));
      const path = request.mode === "navigate" ? "/index.html" : url.pathname;
      const hit = await (await caches.open(running.cache)).match(path);
      // What the release does not list is not served, whatever the server has.
      return hit ?? new Response("Not part of this release", { status: 404 });
    })(),
  );
});

self.addEventListener("message", (event) => {
  // A page asks to look for a newer release now (it came back to the front;
  // `force`: not even a minute since the last look, as tests do).
  if (event.data?.type === "krypt-release-check") {
    event.waitUntil(check(event.data.force === true));
    return;
  }
  if (event.data?.type !== "krypt-release-status") return;
  event.waitUntil(
    (async () => {
      const running = await current();
      event.source?.postMessage({
        type: "krypt-release",
        state: problem ? "refused" : running ? "pinned" : "unpinned",
        release: running?.release,
        commit: running?.commit,
        reason: problem,
      });
    })(),
  );
});

self.addEventListener("push", (event) => {
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      // The app in front already has it, over its own connection.
      if (windows.some((w) => w.focused)) return;
      await self.registration.showNotification("krypt", {
        body: "New activity in your chats",
        // One notification, replaced each time, never a pile.
        tag: "krypt",
        renotify: true,
        icon: "/icon-192.png",
      });
    })(),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const [open] = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      return open ? open.focus() : self.clients.openWindow("/");
    })(),
  );
});
