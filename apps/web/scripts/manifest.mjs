// A release's manifest (docs/releases.md): every file the web app is made
// of, by path, with the SHA-256 of its contents. Signed with the release
// key, it is what the app's service worker checks before running a release.
//
//   node scripts/manifest.mjs write <dist> <release> <commit>
//       writes <dist>/release/manifest.json
//   node scripts/manifest.mjs check <dist> <manifest>
//       <dist> holds exactly the manifest's files (release/ aside)
//   node scripts/manifest.mjs site <origin> <manifest>
//       <origin> serves exactly the manifest's files, and the manifest

import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { parseManifest } from "../src/release/verify.js";

const hash = (bytes) => createHash("sha256").update(bytes).digest("base64");

/** Files Cloudflare reads as settings and never serves. */
const SETTINGS = new Set(["/_headers", "/_redirects"]);

/** Every file under `dist` but release/ and settings, as "/path" → hash, sorted. */
function files(dist) {
  const out = {};
  const walk = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else {
        const web = `/${relative(dist, path).split(sep).join("/")}`;
        if (!web.startsWith("/release/") && !SETTINGS.has(web)) out[web] = hash(readFileSync(path));
      }
    }
  };
  walk(dist);
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)));
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

const [command, ...args] = process.argv.slice(2);
if (command === "write") {
  const [dist, release, commit] = args;
  const manifest = { format: 1, release, commit, files: files(dist) };
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 1)}\n`);
  parseManifest(bytes);
  mkdirSync(join(dist, "release"), { recursive: true });
  writeFileSync(join(dist, "release", "manifest.json"), bytes);
  console.log(`${release}: ${Object.keys(manifest.files).length} files`);
} else if (command === "check") {
  const [dist, path] = args;
  const manifest = parseManifest(readFileSync(path));
  const have = files(dist);
  const problems = [];
  for (const [file, want] of Object.entries(manifest.files)) {
    if (have[file] === undefined) problems.push(`missing ${file}`);
    else if (have[file] !== want) problems.push(`differs ${file}`);
  }
  for (const file of Object.keys(have)) if (!(file in manifest.files)) problems.push(`extra ${file}`);
  if (problems.length) fail(`${dist} is not ${manifest.release}:\n${problems.join("\n")}`);
  console.log(`${dist} is exactly ${manifest.release} (${Object.keys(have).length} files)`);
} else if (command === "site") {
  const [origin, path] = args;
  const bytes = readFileSync(path);
  const manifest = parseManifest(bytes);
  const problems = [];
  const get = async (file) => {
    const response = await fetch(`${origin}${file}`, { headers: { "accept-encoding": "identity" }, cache: "no-store" });
    return response.ok ? Buffer.from(await response.arrayBuffer()) : undefined;
  };
  const served = await get("/release/manifest.json");
  if (!served?.equals(bytes)) problems.push("the manifest served is not this release's");
  for (const [file, want] of Object.entries(manifest.files)) {
    const body = await get(file);
    if (!body) problems.push(`missing ${file}`);
    else if (hash(body) !== want) problems.push(`differs ${file}`);
  }
  if (problems.length) fail(`${origin} does not serve ${manifest.release}:\n${problems.join("\n")}`);
  console.log(`${origin} serves exactly ${manifest.release}`);
} else {
  fail("usage: manifest.mjs write <dist> <release> <commit> | check <dist> <manifest> | site <origin> <manifest>");
}
