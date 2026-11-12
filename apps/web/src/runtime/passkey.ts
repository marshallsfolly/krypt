// @handles and passkey backups (services/edge/src/directory.rs).
//
// A handle is claimed with a passkey, which alone can release it, and with
// this identity's signature, so nobody can point a handle at someone else.
// The passkey also produces a secret (its PRF output) that seals a backup of
// the identity and its contacts; the directory keeps only the sealed bytes.
// Replacing the backup takes a token this device keeps, so it stays current
// without asking for the passkey each time; reading it back takes the
// passkey.

import { native } from "../app/platform";
import { openBackup } from "../core/krypt_wasm.js";
import type { Runtime } from "./device";

const STATE = "krypt.handle";
/** The PRF input: fixed, so the same passkey always yields the same key. */
const PRF_SALT = new TextEncoder().encode("krypt backup prf v1");
/** Backups follow changes after this quiet time. */
const BACKUP_DELAY_MS = 5_000;

export class HandleTaken extends Error {}
export class NoHandle extends Error {}
/** The passkey could not be made or used (cancelled, or unsupported). */
export class PasskeyFailed extends Error {}

/** What this device keeps about its handle. */
export interface HandleState {
  name: string;
  credentialId: string;
  /** Replaces the backup (the directory keeps its hash). */
  token: string;
  /** The passkey's PRF output, which seals the backup; absent if the
   * passkey cannot make one. */
  prf?: string;
  backedUpAt?: number;
}

const b64 = (bytes: ArrayBuffer | Uint8Array) => {
  let text = "";
  for (const b of new Uint8Array(bytes)) text += String.fromCharCode(b);
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
};
const unb64 = (text: string): Uint8Array<ArrayBuffer> => {
  const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
};

/** Passkeys work in browsers; the apps' web views do not support them. */
export const passkeysSupported = () => !native && typeof PublicKeyCredential !== "undefined";

/** A handle as the directory stores it, or undefined if it cannot be one. */
export function normalize(handle: string): string | undefined {
  const h = handle.trim().replace(/^@/, "").toLowerCase();
  return /^[a-z0-9][a-z0-9_]{2,23}$/.test(h) ? h : undefined;
}

export function handleState(): HandleState | undefined {
  try {
    const text = localStorage.getItem(STATE);
    return text ? (JSON.parse(text) as HandleState) : undefined;
  } catch {
    return undefined;
  }
}

function saveState(state: HandleState | undefined) {
  try {
    if (state) localStorage.setItem(STATE, JSON.stringify(state));
    else localStorage.removeItem(STATE);
  } catch {
    // Kept for this session only.
  }
}

async function challenge(base: string, handle: string): Promise<Uint8Array<ArrayBuffer>> {
  const response = await fetch(`${base}/v1/handle/${handle}/challenge`, { method: "POST" });
  if (!response.ok) throw new Error(`challenge: ${response.status}`);
  return unb64(((await response.json()) as { challenge: string }).challenge);
}

const prfOf = (credential: PublicKeyCredential): ArrayBuffer | undefined =>
  (credential.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }).prf?.results?.first;

/** The card a handle points at, if it is claimed. */
export async function lookup(base: string, handle: string): Promise<string | undefined> {
  const h = normalize(handle);
  if (!h) return undefined;
  const response = await fetch(`${base}/v1/handle/${h}`);
  if (!response.ok) return undefined;
  return ((await response.json()) as { card: string }).card;
}

/** Claims `handle` for this device's card with a new passkey, and backs up
 * to it when the passkey can seal backups. */
export async function claim(rt: Runtime, base: string, handle: string): Promise<HandleState> {
  const h = normalize(handle);
  if (!h) throw new NoHandle();
  const issued = await challenge(base, h);
  let credential: PublicKeyCredential;
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        rp: { id: location.hostname, name: "krypt" },
        user: { id: new TextEncoder().encode(h), name: `@${h}`, displayName: `@${h}` },
        challenge: issued,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        attestation: "none",
        extensions: { prf: { eval: { first: PRF_SALT } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch {
    throw new PasskeyFailed();
  }
  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey();
  if (!publicKey) throw new PasskeyFailed();
  const token = crypto.getRandomValues(new Uint8Array(32));
  const answer = await fetch(`${base}/v1/handle/${h}/claim`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      card: rt.contactCard,
      credentialId: b64(credential.rawId),
      publicKey: b64(publicKey),
      clientDataJSON: b64(response.clientDataJSON),
      authenticatorData: b64(response.getAuthenticatorData()),
      identitySignature: b64(rt.signHandle(h, issued)),
      backupToken: b64(token),
    }),
  });
  if (answer.status === 409) throw new HandleTaken();
  if (!answer.ok) throw new Error(`claim: ${answer.status}`);
  // Some passkeys give the PRF output only when used, not when made.
  let prf = prfOf(credential);
  if (!prf) {
    try {
      const used = (await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: location.hostname,
          allowCredentials: [{ type: "public-key", id: credential.rawId }],
          userVerification: "required",
          extensions: { prf: { eval: { first: PRF_SALT } } } as AuthenticationExtensionsClientInputs,
        },
      })) as PublicKeyCredential;
      prf = prfOf(used);
    } catch {
      // No backups with this passkey; the handle still works.
    }
  }
  const state: HandleState = {
    name: h,
    credentialId: b64(credential.rawId),
    token: b64(token),
    ...(prf && { prf: b64(prf) }),
  };
  saveState(state);
  if (state.prf) await backup(rt, base);
  return handleState()!;
}

/** Seals and stores a fresh backup, if this device keeps one. */
export async function backup(rt: Runtime, base: string): Promise<boolean> {
  const state = handleState();
  if (!state?.prf) return false;
  const sealed = await rt.sealBackup(unb64(state.prf));
  const response = await fetch(`${base}/v1/handle/${state.name}/backup`, {
    method: "PUT",
    headers: { "krypt-backup-token": state.token },
    body: sealed,
  });
  if (!response.ok) return false;
  saveState({ ...state, backedUpAt: Date.now() });
  return true;
}

/** Keeps the backup current: after people, chats or conversations change. */
export function keepBackedUp(rt: Runtime, base: string): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stop = rt.onCommit(({ ops, events }) => {
    const changed =
      ops.some((op) => "person" in op || "chat" in op || "forget" in op) ||
      events.some((e) => e.type === "joined" || e.type === "started" || e.type === "membersAdded");
    if (!changed || !handleState()?.prf) return;
    clearTimeout(timer);
    timer = setTimeout(() => void backup(rt, base), BACKUP_DELAY_MS);
  });
  return () => {
    clearTimeout(timer);
    stop();
  };
}

/** What a passkey restores, before the restored device exists. */
export interface Restored {
  handle: string;
  credentialId: string;
  prf: Uint8Array;
  /** For `Runtime.start`: the identity, as a link payload. */
  payload: Uint8Array;
  contacts: string[];
  app: Uint8Array;
}

/** Opens the backup kept with `handle`, using its passkey. */
export async function restore(base: string, handle: string): Promise<Restored> {
  const h = normalize(handle);
  if (!h) throw new NoHandle();
  const issued = await challenge(base, h);
  let credential: PublicKeyCredential;
  try {
    credential = (await navigator.credentials.get({
      publicKey: {
        challenge: issued,
        rpId: location.hostname,
        userVerification: "required",
        extensions: { prf: { eval: { first: PRF_SALT } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch {
    throw new PasskeyFailed();
  }
  const prf = prfOf(credential);
  if (!prf) throw new PasskeyFailed();
  const response = credential.response as AuthenticatorAssertionResponse;
  const answer = await fetch(`${base}/v1/handle/${h}/restore`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      credentialId: b64(credential.rawId),
      clientDataJSON: b64(response.clientDataJSON),
      authenticatorData: b64(response.authenticatorData),
      signature: b64(response.signature),
    }),
  });
  if (answer.status === 404) throw new NoHandle();
  if (!answer.ok) throw new PasskeyFailed();
  const { backup: sealed } = (await answer.json()) as { backup: string | null };
  if (!sealed) throw new NoHandle();
  const opened = openBackup(unb64(sealed), new Uint8Array(prf));
  return { handle: h, credentialId: b64(credential.rawId), prf: new Uint8Array(prf), ...opened };
}

/** On the restored device: points the handle at it (signed by the
 * identity), takes over the backup, and backs up again. */
export async function finishRestore(rt: Runtime, base: string, restored: Restored): Promise<void> {
  const issued = await challenge(base, restored.handle);
  const token = crypto.getRandomValues(new Uint8Array(32));
  const answer = await fetch(`${base}/v1/handle/${restored.handle}/card`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      card: rt.contactCard,
      challenge: b64(issued),
      identitySignature: b64(rt.signHandle(restored.handle, issued)),
      backupToken: b64(token),
    }),
  });
  if (!answer.ok) throw new Error(`card: ${answer.status}`);
  saveState({ name: restored.handle, credentialId: restored.credentialId, token: b64(token), prf: b64(restored.prf) });
  await rt.importApp(restored.app, restored.contacts);
  await backup(rt, base);
}

/** Gives the handle up (with its passkey); the backup goes with it. */
export async function release(base: string): Promise<void> {
  const state = handleState();
  if (!state) return;
  const issued = await challenge(base, state.name);
  let credential: PublicKeyCredential;
  try {
    credential = (await navigator.credentials.get({
      publicKey: {
        challenge: issued,
        rpId: location.hostname,
        allowCredentials: [{ type: "public-key", id: unb64(state.credentialId) }],
        userVerification: "required",
      },
    })) as PublicKeyCredential;
  } catch {
    throw new PasskeyFailed();
  }
  const response = credential.response as AuthenticatorAssertionResponse;
  const answer = await fetch(`${base}/v1/handle/${state.name}/release`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      credentialId: b64(credential.rawId),
      clientDataJSON: b64(response.clientDataJSON),
      authenticatorData: b64(response.authenticatorData),
      signature: b64(response.signature),
    }),
  });
  if (!answer.ok && answer.status !== 404) throw new PasskeyFailed();
  saveState(undefined);
}
