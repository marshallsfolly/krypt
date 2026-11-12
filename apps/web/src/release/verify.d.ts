// Types for verify.js (plain JavaScript, shared with the service worker
// and the tests).

export interface Manifest {
  format: 1;
  /** `vX.Y.Z`. */
  release: string;
  /** The commit it was built from. */
  commit: string;
  /** Path → SHA-256 of its contents, base64. */
  files: Record<string, string>;
}

export const RELEASE_NAMESPACE: string;
export function fromBase64(text: string): Uint8Array;
export function toBase64(bytes: Uint8Array): string;
export function sha256(bytes: BufferSource): Promise<string>;
export function publicKeyBlob(line: string): Uint8Array;
export function verifySignature(message: Uint8Array, armored: string, keyLine: string): Promise<boolean>;
export function parseManifest(bytes: Uint8Array): Manifest;
export function compareReleases(a: string, b: string): -1 | 0 | 1;
export function fetchRelease(
  keyLine: string,
  fetcher?: (url: string, init?: RequestInit) => Promise<Response>,
): Promise<Manifest | undefined>;
