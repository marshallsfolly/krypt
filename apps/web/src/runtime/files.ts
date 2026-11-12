// Moving sealed file parts to and from the edge (`/v1/file/<route>/<id>/<part>`).
// The parts are opaque here: sealing and opening happen in the core.

/** Media the app shows inline, and the type its stored copy gets. Anything
 * else is stored as `application/octet-stream` and only ever saved, never
 * opened: a document opened from a `blob:` URL would run on krypt's origin. */
const INLINE: Record<string, string> = {
  "image/jpeg": "image/jpeg",
  "image/png": "image/png",
  "image/webp": "image/webp",
  "image/gif": "image/gif",
  "image/avif": "image/avif",
  "video/mp4": "video/mp4",
  "video/webm": "video/webm",
  // QuickTime from iPhones: browsers that play it play it as MP4.
  "video/quicktime": "video/mp4",
  // Voice messages.
  "audio/webm": "audio/webm",
  "audio/mp4": "audio/mp4",
};

export type Shown = "image" | "video" | "audio" | "file";

export function shown(mediaType: string): Shown {
  const type = INLINE[mediaType];
  if (!type) return "file";
  return type.startsWith("image/") ? "image" : type.startsWith("audio/") ? "audio" : "video";
}

/** The type a file's stored copy (and its `blob:` URL) gets. */
export function storedType(mediaType: string): string {
  return INLINE[mediaType] ?? "application/octet-stream";
}

/** Downloaded without asking: photos and short videos. */
export const AUTO_DOWNLOAD_MAX = 16 * 1024 * 1024;

export function partUrl(base: string, conversation: string, id: string, part: number): string {
  return `${base}/v1/file/${conversation}/${id}/${part}`;
}

/** Stores one sealed part; resolves with the HTTP status, or 0 if the
 * network failed. XHR, because fetch cannot report upload progress. */
export function putPart(url: string, body: Uint8Array<ArrayBuffer>, auth: string, onProgress: (sent: number) => void): Promise<number> {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url);
    xhr.timeout = 120_000;
    xhr.setRequestHeader("content-type", "application/octet-stream");
    xhr.setRequestHeader("krypt-auth", auth);
    xhr.upload.onprogress = (e) => onProgress(e.loaded);
    xhr.onload = () => resolve(xhr.status);
    xhr.onerror = xhr.ontimeout = xhr.onabort = () => resolve(0);
    xhr.send(body);
  });
}

/** Fetches one sealed part: its bytes, or the HTTP status (0: network). */
export async function getPart(url: string, expected: number, onProgress: (received: number) => void): Promise<Uint8Array | number> {
  let response: Response;
  try {
    response = await fetch(url);
  } catch {
    return 0;
  }
  if (response.status !== 200 || !response.body) return response.status;
  // Never more than the part can hold, whatever the server sends.
  const out = new Uint8Array(expected);
  let at = 0;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (at + value.length > expected) return 502;
      out.set(value, at);
      at += value.length;
      onProgress(at);
    }
  } catch {
    return 0;
  }
  return at === expected ? out : 502;
}

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
