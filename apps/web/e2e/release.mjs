// Release pinning in a real browser (docs/releases.md): a throwaway release
// key, releases built and signed here, and a small server that can be made
// to lie about them. The app must run the signed release it has, take only
// newer signed ones, and say so when it is served anything else.
//
//   node e2e/release.mjs
//
// Needs Chromium (CHROMIUM or PATH) and ssh-keygen; builds with Vite (the
// core in src/core must be built: `just web-core`).

import { execFileSync, execSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import puppeteer from "puppeteer-core";

const web = new URL("..", import.meta.url).pathname;
const work = mkdtempSync(join(tmpdir(), "krypt-release-e2e-"));
const key = join(work, "release");
execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "test release key", "-f", key]);

/** A release: the app built with the test key pinned, its manifest signed
 * (`sign: false` leaves a signature that does not match). */
function release(name, { sign = true, change = "" } = {}) {
  const dist = join(work, name);
  execFileSync("node_modules/.bin/vite", ["build", "--outDir", dist, "--emptyOutDir", "--logLevel", "error"], {
    cwd: web,
    env: { ...process.env, KRYPT_RELEASE_KEY_FILE: `${key}.pub` },
  });
  if (change) {
    // A release that differs in one file: its stylesheet carries a marker.
    const css = readdirSync(join(dist, "assets")).find((f) => f.endsWith(".css"));
    writeFileSync(join(dist, "assets", css), `${readFileSync(join(dist, "assets", css), "utf8")}\n/* ${change} */\n`);
  }
  execFileSync("node", ["scripts/manifest.mjs", "write", dist, name, "c".repeat(40)], { cwd: web, stdio: "ignore" });
  const manifest = join(dist, "release", "manifest.json");
  execFileSync("ssh-keygen", ["-q", "-Y", "sign", "-f", key, "-n", "krypt-release", manifest]);
  if (!sign) {
    // One character of the signature changed: it no longer verifies.
    const signature = readFileSync(`${manifest}.sig`, "utf8");
    const flip = signature.replace(/[A-Za-z](?=[A-Za-z0-9+/]*=*\n-----END)/, (c) => (c === "A" ? "B" : "A"));
    writeFileSync(`${manifest}.sig`, flip);
  }
  return dist;
}

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json" };
let site = "";
const server = createServer((request, response) => {
  const path = new URL(request.url, "http://x").pathname;
  const file = join(site, path === "/" ? "index.html" : path);
  try {
    const body = readFileSync(file);
    response.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    response.end(body);
  } catch {
    response.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
/** Serves `dist` from now on (a copy, so it can be tampered with). */
const serve = (dist) => {
  site = join(work, `site-${Math.random()}`);
  cpSync(dist, site, { recursive: true });
};

const failures = [];
const step = async (name, run) => {
  try {
    await run();
    console.log(`ok   ${name}`);
  } catch (error) {
    failures.push(name);
    console.log(`FAIL ${name}: ${error.message}`);
  }
};
const until = async (what, test, ms = 20_000) => {
  const end = Date.now() + ms;
  for (;;) {
    const value = await test();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 200));
  }
};

const v1 = release("v0.0.1");
const v2 = release("v0.0.2", { change: "release two" });
const executablePath = process.env.CHROMIUM ?? execSync("command -v chromium").toString().trim();
const browser = await puppeteer.launch({ executablePath, headless: true, args: ["--no-sandbox"] });
const page = await browser.newPage();
page.on("pageerror", (e) => console.log(`page error: ${e.message}`));

/** What the service worker says it runs, asked directly. */
const status = () =>
  page.evaluate(
    () =>
      new Promise((resolve) => {
        const controller = navigator.serviceWorker.controller;
        if (!controller) return resolve(undefined);
        const listen = (event) => {
          if (event.data?.type !== "krypt-release") return;
          navigator.serviceWorker.removeEventListener("message", listen);
          resolve(event.data);
        };
        navigator.serviceWorker.addEventListener("message", listen);
        controller.postMessage({ type: "krypt-release-status" });
        setTimeout(() => resolve(undefined), 2_000);
      }),
  );
const check = () => page.evaluate(() => navigator.serviceWorker.controller?.postMessage({ type: "krypt-release-check", force: true }));
const stylesheet = () =>
  page.evaluate(async () => {
    const href = document.querySelector('link[rel="stylesheet"]')?.getAttribute("href");
    return href ? (await fetch(href)).text() : "";
  });

await step("a signed release is pinned", async () => {
  serve(v1);
  await page.goto(origin);
  await until("the service worker", () => page.evaluate(() => !!navigator.serviceWorker.controller), 30_000).catch(async () => {
    await page.reload();
    await until("the service worker", () => page.evaluate(() => !!navigator.serviceWorker.controller));
  });
  const s = await until("pinning", async () => {
    const s = await status();
    return s?.state === "pinned" && s;
  });
  if (s.release !== "v0.0.1") throw new Error(`running ${s.release}`);
});

await step("a file changed on the server is never served", async () => {
  const before = await stylesheet();
  const css = readdirSync(join(site, "assets")).find((f) => f.endsWith(".css"));
  writeFileSync(join(site, "assets", css), "body { display: none }");
  await page.reload();
  if ((await stylesheet()) !== before) throw new Error("the changed file was served");
});

await step("a newer release with a file that is not the signed one is refused", async () => {
  serve(v2);
  const css = readdirSync(join(site, "assets")).find((f) => f.endsWith(".css"));
  writeFileSync(join(site, "assets", css), "body { display: none }");
  await check();
  const s = await until("refusal", async () => {
    const s = await status();
    return s?.state === "refused" && s;
  });
  if (!/not the file the release signed/.test(s.reason)) throw new Error(s.reason);
  await page.reload();
  await page.waitForSelector(".release-warning", { timeout: 10_000 }).catch(() => {
    throw new Error("no warning shown");
  });
  if ((await status())?.release !== "v0.0.1") throw new Error("no longer v0.0.1");
});

await step("an unsigned release is refused", async () => {
  serve(release("v0.0.3", { sign: false, change: "unsigned" }));
  await check();
  const s = await until("refusal", async () => {
    const s = await status();
    return s?.state === "refused" && /not signed/.test(s.reason ?? "") && s;
  });
  if (s.release !== "v0.0.1") throw new Error(`running ${s.release}`);
});

await step("a newer signed release is taken", async () => {
  serve(v2);
  await check();
  await until("v0.0.2", async () => (await status())?.release === "v0.0.2");
  await page.reload();
  if (!(await stylesheet()).includes("release two")) throw new Error("still the old files");
});

await step("an older release is refused", async () => {
  serve(v1);
  await check();
  const s = await until("refusal", async () => {
    const s = await status();
    return s?.state === "refused" && s;
  });
  if (!/older release/.test(s.reason)) throw new Error(s.reason);
});

await step("an unsigned service worker is noticed", async () => {
  serve(v2);
  await page.reload();
  await until("v0.0.2", async () => (await status())?.release === "v0.0.2");
  writeFileSync(join(site, "sw.js"), `${readFileSync(join(site, "sw.js"), "utf8")}\n// changed\n`);
  await page.evaluate(async () => (await navigator.serviceWorker.getRegistration())?.update());
  await page.waitForSelector(".release-warning", { timeout: 15_000 });
});

await browser.close();
server.close();
rmSync(work, { recursive: true, force: true });
console.log(failures.length ? `${failures.length} failed` : "all passed");
process.exit(failures.length ? 1 : 0);
