// Tests for release checking (src/release/verify.js): `node --test
// scripts/release.test.mjs`. Real signatures from `ssh-keygen -Y sign` with
// a throwaway key; hardware-key signatures (sk-ssh-ed25519, sk-ecdsa) built
// here as OpenSSH lays them out (PROTOCOL.sshsig, PROTOCOL.u2f), since no
// hardware key is at hand.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  compareReleases,
  parseManifest,
  RELEASE_NAMESPACE,
  toBase64,
  verifySignature,
} from "../src/release/verify.js";

const dir = mkdtempSync(join(tmpdir(), "krypt-release-test-"));
const keygen = (name) => {
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", name, "-f", join(dir, name)]);
  return readFileSync(join(dir, `${name}.pub`), "utf8");
};
const sign = (key, message, namespace = RELEASE_NAMESPACE) => {
  const file = join(dir, `message-${Math.random()}`);
  writeFileSync(file, message);
  execFileSync("ssh-keygen", ["-q", "-Y", "sign", "-f", join(dir, key), "-n", namespace, file]);
  return readFileSync(`${file}.sig`, "utf8");
};

const releaseKey = keygen("release");
const otherKey = keygen("other");
const manifest = Buffer.from(
  `${JSON.stringify({ format: 1, release: "v1.2.3", commit: "a".repeat(40), files: { "/index.html": "A".repeat(43) + "=" } })}\n`,
);

test("a release signed by the release key verifies", async () => {
  assert.equal(await verifySignature(manifest, sign("release", manifest), releaseKey), true);
});

test("anything else does not", async () => {
  const signature = sign("release", manifest);
  const changed = Buffer.from(manifest.toString().replace("v1.2.3", "v9.9.9"));
  assert.equal(await verifySignature(changed, signature, releaseKey), false, "another message");
  assert.equal(await verifySignature(manifest, sign("other", manifest), releaseKey), false, "another key");
  assert.equal(await verifySignature(manifest, signature, otherKey), false, "pinned to another key");
  assert.equal(await verifySignature(manifest, sign("release", manifest, "file"), releaseKey), false, "another namespace");
  assert.equal(await verifySignature(manifest, "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----", releaseKey), false);
  assert.equal(await verifySignature(manifest, "", releaseKey), false);
});

// ---- Hardware keys, laid out as OpenSSH does -------------------------------

const enc = new TextEncoder();
const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const str = (bytes) => concat(u32(bytes.length), typeof bytes === "string" ? enc.encode(bytes) : bytes);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(typeof p === "string" ? enc.encode(p) : p, at);
    at += p.length;
  }
  return out;
};
const sha = async (name, bytes) => new Uint8Array(await crypto.subtle.digest(name, bytes));
const mpint = (bytes) => {
  let b = bytes;
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
  return str(b[0] & 0x80 ? concat(Uint8Array.of(0), b) : b);
};

/** A signature from a hardware key of `type`, as `ssh-keygen -Y sign` makes it. */
async function hardware(type, message, flags = 0x01) {
  const application = "ssh:krypt-release";
  const ed = type === "sk-ssh-ed25519@openssh.com";
  const pair = ed
    ? await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])
    : await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const keyBlob = ed
    ? concat(str(type), str(raw), str(application))
    : concat(str(type), str("nistp256"), str(raw), str(application));
  const signed = concat(enc.encode("SSHSIG"), str(RELEASE_NAMESPACE), str(""), str("sha512"), str(await sha("SHA-512", message)));
  const counter = u32(7);
  const wrapped = concat(await sha("SHA-256", enc.encode(application)), Uint8Array.of(flags), counter, await sha("SHA-256", signed));
  const sig = new Uint8Array(
    await crypto.subtle.sign(ed ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, wrapped),
  );
  const inner = ed ? sig : concat(mpint(sig.subarray(0, 32)), mpint(sig.subarray(32)));
  const sigBlob = concat(str(type), str(inner), Uint8Array.of(flags), counter);
  const sshsig = concat(enc.encode("SSHSIG"), u32(1), str(keyBlob), str(RELEASE_NAMESPACE), str(""), str("sha512"), str(sigBlob));
  return {
    key: `${type} ${toBase64(keyBlob)} release`,
    signature: `-----BEGIN SSH SIGNATURE-----\n${toBase64(sshsig)}\n-----END SSH SIGNATURE-----\n`,
  };
}

for (const type of ["sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]) {
  test(`a hardware key (${type}) verifies, only when touched`, async () => {
    const touched = await hardware(type, manifest);
    assert.equal(await verifySignature(manifest, touched.signature, touched.key), true);
    const changed = Buffer.from(manifest.toString().replace("v1.2.3", "v9.9.9"));
    assert.equal(await verifySignature(changed, touched.signature, touched.key), false);
    const untouched = await hardware(type, manifest, 0x00);
    assert.equal(await verifySignature(manifest, untouched.signature, untouched.key), false);
  });
}

// ---- Manifests and releases ------------------------------------------------

test("manifests are strict", () => {
  const make = (patch) =>
    Buffer.from(
      JSON.stringify({ format: 1, release: "v1.0.0", commit: "b".repeat(40), files: { "/index.html": "B".repeat(43) + "=" }, ...patch }),
    );
  assert.equal(parseManifest(make({})).release, "v1.0.0");
  for (const bad of [
    { format: 2 },
    { release: "1.0.0" },
    { commit: "short" },
    { files: {} },
    { files: { "/app.js": "B".repeat(43) + "=" } },
    { files: { "/index.html": "B".repeat(43) + "=", "/../etc": "B".repeat(43) + "=" } },
    { files: { "/index.html": "B".repeat(43) + "=", "/release/x": "B".repeat(43) + "=" } },
    { files: { "/index.html": "not a hash" } },
  ]) {
    assert.throws(() => parseManifest(make(bad)), `${JSON.stringify(bad)} accepted`);
  }
});

test("releases only move forward", () => {
  assert.equal(compareReleases("v1.2.3", "v1.2.3"), 0);
  assert.equal(compareReleases("v1.2.10", "v1.2.9"), 1);
  assert.equal(compareReleases("v0.9.9", "v1.0.0"), -1);
});
