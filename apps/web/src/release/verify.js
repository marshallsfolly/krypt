// Checking a release (docs/releases.md): its manifest, signed with the
// release key by `ssh-keygen -Y sign -n krypt-release`, and the files it
// lists. Shared, as it is, by the app, its service worker (which inlines
// this file at build time) and the tests: plain JavaScript over WebCrypto,
// nothing imported.
//
// The release key is an SSH key: on a YubiKey (`sk-ssh-ed25519@openssh.com`
// or, on older ones, `sk-ecdsa-sha2-nistp256@openssh.com`), or a plain
// `ssh-ed25519` key for tests. A hardware key's signature also says the key
// was touched, which is required.

export const RELEASE_NAMESPACE = "krypt-release";
const SSHSIG_MAGIC = "SSHSIG";
const SK_USER_PRESENT = 0x01;

const utf8 = new TextEncoder();

/** Base64 to bytes (no padding needed). */
export function fromBase64(text) {
  const binary = atob(text.replace(/\s+/g, ""));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function toBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** SHA-256 of `bytes`, base64: how the manifest names a file's contents. */
export async function sha256(bytes) {
  return toBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** Reads SSH wire encoding: lengths are 32-bit big-endian. */
class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.at = 0;
  }
  take(n) {
    if (n < 0 || this.at + n > this.bytes.length) throw new Error("truncated");
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }
  u8() {
    return this.take(1)[0];
  }
  u32() {
    const b = this.take(4);
    return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  }
  string() {
    return this.take(this.u32());
  }
  text() {
    return new TextDecoder("utf-8", { fatal: true }).decode(this.string());
  }
  done() {
    if (this.at !== this.bytes.length) throw new Error("trailing bytes");
  }
}

function sshString(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function equal(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** The public key blob of an OpenSSH public key line ("type base64 [comment]"). */
export function publicKeyBlob(line) {
  const [type, data] = line.trim().split(/\s+/);
  if (!type || !data) throw new Error("not an SSH public key");
  const blob = fromBase64(data);
  if (new Reader(blob).text() !== type) throw new Error("key type mismatch");
  return blob;
}

/** A key blob's parts: type, the raw key, and (hardware keys) the application. */
function parseKey(blob) {
  const r = new Reader(blob);
  const type = r.text();
  let key;
  let application;
  if (type === "ssh-ed25519") {
    key = r.string();
  } else if (type === "sk-ssh-ed25519@openssh.com") {
    key = r.string();
    application = r.string();
  } else if (type === "sk-ecdsa-sha2-nistp256@openssh.com") {
    if (r.text() !== "nistp256") throw new Error("not P-256");
    key = r.string();
    application = r.string();
  } else {
    throw new Error(`unsupported key type ${type}`);
  }
  r.done();
  return { type, key, application };
}

/** An ECDSA signature's SSH mpints r and s, as the 64 bytes WebCrypto takes. */
function ecdsaRaw(blob) {
  const r = new Reader(blob);
  const fixed = (mpint) => {
    let bytes = mpint;
    while (bytes.length > 32 && bytes[0] === 0) bytes = bytes.subarray(1);
    if (bytes.length > 32) throw new Error("bad ECDSA signature");
    const out = new Uint8Array(32);
    out.set(bytes, 32 - bytes.length);
    return out;
  };
  const out = concat(fixed(r.string()), fixed(r.string()));
  r.done();
  return out;
}

/**
 * Whether `armored` (an `ssh-keygen -Y sign` signature) signs `message` in
 * the release namespace with exactly the pinned key `keyLine`.
 */
export async function verifySignature(message, armored, keyLine) {
  try {
    const body = armored
      .replace("-----BEGIN SSH SIGNATURE-----", "")
      .replace("-----END SSH SIGNATURE-----", "");
    const r = new Reader(fromBase64(body));
    if (new TextDecoder().decode(r.take(6)) !== SSHSIG_MAGIC) return false;
    if (r.u32() !== 1) return false;
    const signer = r.string();
    const namespace = r.string();
    const reserved = r.string();
    const hashName = new TextDecoder().decode(r.string());
    const signature = new Reader(r.string());
    r.done();
    // Only the pinned key, only for releases.
    if (!equal(signer, publicKeyBlob(keyLine))) return false;
    if (new TextDecoder().decode(namespace) !== RELEASE_NAMESPACE) return false;
    const hash = { sha512: "SHA-512", sha256: "SHA-256" }[hashName];
    if (!hash) return false;
    const digest = new Uint8Array(await crypto.subtle.digest(hash, message));
    // What `ssh-keygen -Y sign` signs (PROTOCOL.sshsig).
    const signed = concat(
      utf8.encode(SSHSIG_MAGIC),
      sshString(namespace),
      sshString(reserved),
      sshString(utf8.encode(hashName)),
      sshString(digest),
    );
    const key = parseKey(signer);
    if (signature.text() !== key.type) return false;
    const raw = signature.string();
    if (key.type === "ssh-ed25519") {
      signature.done();
      return await ed25519(key.key, raw, signed);
    }
    // A hardware key signs SHA-256(application) ‖ flags ‖ counter ‖
    // SHA-256(data) (PROTOCOL.u2f), and must have been touched.
    const flags = signature.u8();
    const counter = signature.take(4);
    signature.done();
    if ((flags & SK_USER_PRESENT) === 0) return false;
    const sha = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    const wrapped = concat(await sha(key.application), Uint8Array.of(flags), counter, await sha(signed));
    if (key.type === "sk-ssh-ed25519@openssh.com") return await ed25519(key.key, raw, wrapped);
    const ecKey = await crypto.subtle.importKey("raw", key.key, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, ecKey, ecdsaRaw(raw), wrapped);
  } catch {
    return false;
  }
}

async function ed25519(publicKey, signature, data) {
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
}

/** A manifest's contents, once its signature checked out: or why not. */
export function parseManifest(bytes) {
  const manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (manifest.format !== 1) throw new Error("unknown manifest format");
  if (!/^v\d+\.\d+\.\d+$/.test(manifest.release)) throw new Error("bad release name");
  if (!/^[0-9a-f]{40}$/.test(manifest.commit)) throw new Error("bad commit");
  const files = Object.entries(manifest.files ?? {});
  if (files.length === 0 || !files.some(([path]) => path === "/index.html")) throw new Error("no app in it");
  for (const [path, hash] of files) {
    if (!/^\/[A-Za-z0-9._\-/]+$/.test(path) || path.includes("..") || path.startsWith("/release/")) {
      throw new Error(`bad path ${path}`);
    }
    if (!/^[A-Za-z0-9+/]{43}=$/.test(hash)) throw new Error(`bad hash for ${path}`);
  }
  return manifest;
}

/** -1, 0 or 1, as release `a` is older than, the same as or newer than `b`. */
export function compareReleases(a, b) {
  const parts = (v) => v.slice(1).split(".").map(Number);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

/**
 * Fetches a release's manifest and signature from `origin` and checks
 * them against the pinned key: the manifest, or `undefined` when there is
 * none (a development build), or an error saying what is wrong.
 */
export async function fetchRelease(keyLine, fetcher = fetch) {
  const [manifest, signature] = await Promise.all([
    fetcher("/release/manifest.json", { cache: "no-store" }),
    fetcher("/release/manifest.json.sig", { cache: "no-store" }),
  ]);
  if (manifest.status === 404 && signature.status === 404) return undefined;
  if (!manifest.ok || !signature.ok) throw new Error("the release could not be fetched");
  const bytes = new Uint8Array(await manifest.arrayBuffer());
  if (!(await verifySignature(bytes, await signature.text(), keyLine))) {
    throw new Error("the release is not signed by the release key");
  }
  return parseManifest(bytes);
}
