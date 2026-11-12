// Linking devices. The new device leaves its (post-quantum) public key at a
// drop and shows a code; the existing device scans it, fetches the key,
// leaves the identity sealed for it at a second drop, and the new device
// answers with its card through a third, so the existing one can add it to
// every conversation. Drops only ever hold a public key or ciphertext, and
// are emptied when read.

import { sleep } from "./files";

const POLL_MS = 2_000;
/** A drop lasts ten minutes; nobody waits longer. */
const WAIT_MS = 10 * 60_000;

export class LinkTimedOut extends Error {}
/** The code's key is gone: the code was used already, or has expired. */
export class LinkCodeUsed extends Error {}

/** Leaves sealed bytes at a drop. */
export async function put(base: string, drop: string, sealed: Uint8Array<ArrayBuffer>): Promise<void> {
  const response = await fetch(`${base}/v1/drop/${drop}`, { method: "PUT", body: sealed });
  if (!response.ok) throw new Error(`drop refused: ${response.status}`);
}

/** Takes what is at a drop now (emptying it), if anything. */
export async function takeNow(base: string, drop: string): Promise<Uint8Array | undefined> {
  const response = await fetch(`${base}/v1/drop/${drop}`);
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`drop refused: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

/** Waits for sealed bytes at a drop (taking them empties it). */
export async function take(base: string, drop: string, signal: AbortSignal): Promise<Uint8Array> {
  const until = Date.now() + WAIT_MS;
  while (Date.now() < until) {
    if (signal.aborted) throw new LinkTimedOut();
    try {
      const response = await fetch(`${base}/v1/drop/${drop}`, { signal });
      if (response.ok) return new Uint8Array(await response.arrayBuffer());
    } catch {
      // Offline for a moment, or cancelled: the loop decides.
    }
    await sleep(POLL_MS);
  }
  throw new LinkTimedOut();
}
