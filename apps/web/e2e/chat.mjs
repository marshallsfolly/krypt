// End to end in real browsers: two devices (isolated browser contexts) meet
// by contact card and chat through the mailbox, then one reloads and finds
// everything still there, and a second tab defers to the first.
//
//   KRYPT_URL=http://127.0.0.1:8788 node e2e/chat.mjs [screenshot-dir]
//
// Needs the edge running (`just edge-dev`) and Chromium (CHROMIUM or PATH).

import { execFileSync, execSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import puppeteer from "puppeteer-core";

const url = process.env.KRYPT_URL ?? "http://127.0.0.1:8788";
const shots = process.argv[2];
const executablePath = process.env.CHROMIUM ?? execSync("command -v chromium").toString().trim();
const timeout = 20_000;

// CHROMIUM_ARGS, e.g. "--host-resolver-rules=MAP krypt.chat 104.21.28.84"
// while a local DNS cache is stale.
const extra = process.env.CHROMIUM_ARGS ? [process.env.CHROMIUM_ARGS] : [];
// Calls use a fake camera and microphone (a test pattern and a tone), and
// real local addresses so two contexts on one machine connect directly.
const media = [
  "--use-fake-ui-for-media-stream",
  "--use-fake-device-for-media-stream",
  "--disable-features=WebRtcHideLocalIpsWithMdns",
  "--autoplay-policy=no-user-gesture-required",
];
const browser = await puppeteer.launch({ executablePath, headless: true, args: ["--no-sandbox", ...media, ...extra] });
const failures = [];
const step = async (name, run) => {
  const started = performance.now();
  try {
    await run();
    console.log(`ok   ${name} (${Math.round(performance.now() - started)} ms)`);
  } catch (error) {
    failures.push(name);
    console.log(`FAIL ${name}: ${error.message}`);
  }
};

async function device(name) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  page.setDefaultTimeout(timeout);
  await page.setViewport({ width: 420, height: 860, deviceScaleFactor: 2 });
  page.on("pageerror", (e) => console.log(`[${name}] page error: ${e.message}`));
  page.on("console", (m) => m.type() === "error" && console.log(`[${name}] console: ${m.text()}`));
  await page.goto(url);
  return { name, context, page };
}

const text = (page, selector) => page.$eval(selector, (e) => e.textContent ?? "");
/** Back to the chat list, from however deep. */
const back = async (page) => {
  for (let i = 0; i < 3; i++) {
    const button = await page.$('button[aria-label="Back"]');
    if (!button || !(await button.isVisible())) return;
    await button.click();
    await new Promise((r) => setTimeout(r, 150));
  }
};
const click = (page, label) => page.locator(`::-p-text(${label})`).click();
// After entrance animations (Soft's springs run ~0.8 s) have settled.
const shot = async (page, name) => {
  if (!shots) return;
  await new Promise((r) => setTimeout(r, 1200));
  await page.screenshot({ path: `${shots}/${name}.png` });
};

const alice = await device("alice");
const bob = await device("bob");
let aliceCard = "";

await step("a new person gets a short tour of how krypt works, then their identity", async () => {
  // Alice reads every page; Bob skips.
  for (const title of ["Welcome to krypt", "Connect with your card", "Check it's really them", "Only your devices hold the keys"]) {
    await alice.page.waitForSelector(`.tour-page[data-active="true"] h1::-p-text(${title})`);
    await alice.page.locator(".tour-foot .btn").click();
  }
  await bob.page.locator("::-p-text(Skip)").click();
  for (const d of [alice, bob]) {
    await d.page.waitForSelector('.tour-end[data-active="true"]');
    await d.page.waitForSelector("::-p-text(Identity ready)");
    const fingerprint = await text(d.page, ".fingerprint");
    if (!/^[0-9A-F]{4}( [0-9A-F]{4}){3}$/.test(fingerprint)) throw new Error(`fingerprint ${fingerprint}`);
    const [theme, pickers] = await d.page.evaluate(() => [document.documentElement.dataset.theme, document.querySelectorAll(".theme-cards").length]);
    if (theme !== "glass" || pickers !== 0) throw new Error(`first launch shows ${theme}, ${pickers} theme pickers`);
  }
  await shot(alice.page, "1-onboarding");
  for (const d of [alice, bob]) await click(d.page, "Continue");
});

await step("alice shares her card", async () => {
  await alice.page.locator('button[aria-label="My card"]').click();
  aliceCard = (await alice.page.waitForSelector(".card-text").then((e) => e.evaluate((n) => n.textContent))).trim();
  if (!aliceCard.startsWith("krypt:")) throw new Error(`card ${aliceCard}`);
  await shot(alice.page, "2-card");
});

await step("her QR code decodes to her card's link", async () => {
  const file = join(mkdtempSync(join(tmpdir(), "krypt-qr-")), "qr.png");
  await alice.page.waitForSelector(".qr-plate").then((e) => e.screenshot({ path: file }));
  const decoded = execFileSync("zbarimg", ["--raw", "-q", file]).toString().trim();
  const expected = `${new URL(url).origin}/#add=${aliceCard}`;
  if (decoded !== expected) throw new Error(`decoded ${decoded}, expected ${expected}`);
  await alice.page.keyboard.press("Escape");
});

await step("bob starts a chat from alice's card", async () => {
  await click(bob.page, "New chat");
  await bob.page.locator(".sheet textarea").fill(aliceCard);
  await bob.page.locator('.sheet input[placeholder="Optional"]').fill("Alice");
  await click(bob.page, "Start chat");
  await bob.page.waitForSelector(".pane-chat");
});

await step("bob's chat reaches alice as a request, and she accepts it", async () => {
  await alice.page.locator(".requests").click();
  await alice.page.locator(".requests-list .list-item").click();
  await alice.page.waitForSelector("::-p-text(You joined.)");
  await alice.page.waitForSelector(".request-bar");
  await alice.page.$$eval(".request-bar button", (bs) => bs.find((b) => b.textContent === "Accept").click());
  await alice.page.waitForSelector(".composer textarea");
});

await step("bob's message reaches alice, pushed", async () => {
  await bob.page.locator(".composer textarea").fill("hello alice");
  await bob.page.keyboard.press("Enter");
  await alice.page.waitForSelector("::-p-text(hello alice)");
  await bob.page.waitForFunction(() => [...document.querySelectorAll(".msg.mine .msg-state")].some((e) => e.textContent === "Sent"));
});

await step("alice replies and bob gets it", async () => {
  await alice.page.locator(".composer textarea").fill("hi bob ✦ this is end-to-end encrypted");
  await alice.page.keyboard.press("Enter");
  await bob.page.waitForSelector("::-p-text(hi bob ✦ this is end-to-end encrypted)");
  await shot(bob.page, "3-chat-glass");
});

/** Puts a page in the background (`hidden`) or brings it back, as switching
 * apps does. */
const visibility = (page, state) =>
  page.evaluate((state) => {
    if (state === "visible") delete document.visibilityState;
    else Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
    document.dispatchEvent(new Event("visibilitychange"));
  }, state);
const status = (page) => page.$eval(".pane-chat .bar .status", (e) => e.textContent ?? "");
const clearDraft = async (page) => {
  await page.locator(".composer textarea").click();
  await page.keyboard.down("Control");
  await page.keyboard.press("a");
  await page.keyboard.up("Control");
  await page.keyboard.press("Backspace");
};

await step("each sees the other online; bob sees alice typing until she stops", async () => {
  for (const d of [alice, bob]) {
    await d.page.waitForFunction(() => document.querySelector(".pane-chat .bar .status")?.textContent === "online", { timeout: 15_000 });
  }
  await alice.page.type(".composer textarea", "one moment");
  await bob.page.waitForSelector(".pane-chat .typing");
  if ((await status(bob.page)) !== "typing…") throw new Error(`bob's header says ${await status(bob.page)}`);
  await shot(bob.page, "3b-typing");
  // Clearing the draft stops it at once (not after the pause).
  await clearDraft(alice.page);
  await bob.page.waitForFunction(() => !document.querySelector(".pane-chat .typing"), { timeout: 3_000 });
  // Switching away is going offline; coming back, online again.
  await visibility(alice.page, "hidden");
  await bob.page.waitForFunction(() => document.querySelector(".pane-chat .bar .status")?.textContent !== "online", { timeout: 5_000 });
  await visibility(alice.page, "visible");
  await bob.page.waitForFunction(() => document.querySelector(".pane-chat .bar .status")?.textContent === "online", { timeout: 5_000 });
});

await step("with typing indicators off, nobody sees you type, and you see no one", async () => {
  /** Flips alice's switch in Settings → Privacy, and goes back to the chat. */
  const flip = async (page) => {
    await back(page);
    await page.locator('button[aria-label="Settings"]').click();
    await page.$$eval(".settings-menu .headline", (es) => es.find((e) => e.textContent === "Privacy and safety").click());
    await page.locator("::-p-text(Typing indicators)").click();
    await back(page);
    await page.locator(".list-item").click();
    await page.waitForSelector(".composer textarea");
  };
  await flip(alice.page);
  await alice.page.type(".composer textarea", "a secret draft");
  await bob.page.type(".composer textarea", "x");
  await new Promise((resolve) => setTimeout(resolve, 2_500));
  for (const d of [alice, bob]) {
    if (await d.page.$(".pane-chat .typing")) throw new Error(`${d.name} saw typing with alice's indicators off`);
  }
  for (const d of [alice, bob]) await clearDraft(d.page);
  await flip(alice.page);
});

/** Opens the actions of the message saying `text` (desktop: its "More"
 * button, shown on hover). */
async function actions(page, text) {
  await page.waitForSelector(`.pane-chat article.msg ::-p-text(${text})`);
  await page.evaluate((text) => {
    const article = [...document.querySelectorAll(".pane-chat article.msg")].findLast((a) => a.querySelector(".msg-body")?.textContent === text);
    article.querySelector(".msg-more").click();
  }, text);
  await page.waitForSelector('.sheet[open][aria-label="Message actions"]');
}
const choice = (page, label) =>
  page.$$eval(".sheet[open] .action-list button", (bs, label) => bs.find((b) => b.textContent === label).click(), label);

await step("bob reacts to alice's message and replies to it; alice sees both", async () => {
  const original = "hi bob ✦ this is end-to-end encrypted";
  await actions(bob.page, original);
  await bob.page.$$eval(".sheet[open] .reaction-pick", (bs) => bs.find((b) => b.textContent === "👍").click());
  await alice.page.waitForSelector(".pane-chat .reaction::-p-text(👍)");
  await actions(bob.page, original);
  await choice(bob.page, "Reply");
  await bob.page.waitForSelector(".composer-context ::-p-text(Replying to Alice)");
  await bob.page.locator(".composer textarea").fill("agreed, it is");
  await bob.page.keyboard.press("Enter");
  await alice.page.waitForSelector(".pane-chat .msg-body ::-p-text(agreed, it is)");
  const quote = await alice.page.evaluate(() => {
    const article = [...document.querySelectorAll(".pane-chat article.msg")].find((a) => a.querySelector(".msg-body")?.textContent?.endsWith("agreed, it is"));
    return article?.querySelector(".msg-quote")?.textContent ?? "";
  });
  if (!quote.includes("this is end-to-end encrypted")) throw new Error(`quote ${quote}`);
  // Taking the reaction back.
  await actions(bob.page, original);
  await bob.page.$$eval(".sheet[open] .reaction-pick", (bs) => bs.find((b) => b.textContent === "👍").click());
  await alice.page.waitForFunction(() => !document.querySelector(".pane-chat .reaction"));
  await shot(alice.page, "3c-reply");
});

await step("alice edits one message and deletes another for everyone", async () => {
  await alice.page.locator(".composer textarea").fill("see you at noen");
  await alice.page.keyboard.press("Enter");
  await bob.page.waitForSelector("::-p-text(see you at noen)");
  await actions(alice.page, "see you at noen");
  await choice(alice.page, "Edit");
  await alice.page.waitForSelector(".composer-context ::-p-text(Editing your message)");
  await clearDraft(alice.page);
  await alice.page.type(".composer textarea", "see you at noon");
  await alice.page.keyboard.press("Enter");
  await bob.page.waitForSelector(".pane-chat .msg-body::-p-text(see you at noon)");
  await bob.page.waitForSelector(".pane-chat .msg-edited");
  if (await bob.page.$(".pane-chat .msg-body::-p-text(see you at noen)")) throw new Error("the old text is still shown");
  await alice.page.locator(".composer textarea").fill("wrong chat, sorry");
  await alice.page.keyboard.press("Enter");
  await bob.page.waitForSelector("::-p-text(wrong chat, sorry)");
  await actions(alice.page, "wrong chat, sorry");
  await choice(alice.page, "Delete for everyone");
  for (const d of [alice, bob]) {
    await d.page.waitForFunction(() => !document.querySelector(".pane-chat .msg-body")?.closest(".pane-chat") || ![...document.querySelectorAll(".pane-chat .msg-body")].some((b) => b.textContent === "wrong chat, sorry"));
    await d.page.waitForSelector(".pane-chat .msg-body.deleted::-p-text(This message was deleted)");
  }
});

await step("alice sees her messages read; with read receipts off, neither side sees it", async () => {
  // Bob has the chat open, so alice's newest message is read.
  const lastState = (page) => page.$$eval(".pane-chat article.msg.mine .msg-state", (s) => s.at(-1)?.textContent?.trim() ?? "");
  await alice.page.waitForFunction(() => [...document.querySelectorAll(".pane-chat article.msg.mine .msg-state")].at(-1)?.textContent?.trim() === "Read", { timeout: 15_000 });
  const flip = async (page) => {
    await back(page);
    await page.locator('button[aria-label="Settings"]').click();
    await page.$$eval(".settings-menu .headline", (es) => es.find((e) => e.textContent === "Privacy and safety").click());
    await page.locator("::-p-text(Read receipts)").click();
    await back(page);
    await page.locator(".list-item").click();
    await page.waitForSelector(".composer textarea");
  };
  await flip(alice.page);
  if ((await lastState(alice.page)) !== "Sent") throw new Error(`with receipts off alice sees ${await lastState(alice.page)}`);
  await bob.page.locator(".composer textarea").fill("did you get that?");
  await bob.page.keyboard.press("Enter");
  await alice.page.waitForSelector("::-p-text(did you get that?)");
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  if ((await lastState(bob.page)) !== "Sent") throw new Error(`alice sent a receipt with them off: ${await lastState(bob.page)}`);
  await flip(alice.page);
});

await step("bob records a voice message; alice plays it, with no recorder metadata", async () => {
  await bob.page.locator('button[aria-label="Record a voice message"]').click();
  await bob.page.waitForSelector(".recorder");
  await new Promise((resolve) => setTimeout(resolve, 2_000));
  await bob.page.locator('button[aria-label="Send voice message"]').click();
  await alice.page.waitForSelector(".pane-chat .voice");
  await alice.page.waitForSelector('.pane-chat .voice button[aria-label="Play voice message"]:not([disabled])');
  const duration = await alice.page.$eval(".pane-chat .voice .voice-time", (e) => e.textContent);
  if (!/^0:0[1-3]$/.test(duration)) throw new Error(`duration ${duration}`);
  // Downloaded automatically, then played.
  await alice.page.waitForFunction(async () => {
    const db = await new Promise((resolve) => {
      const r = indexedDB.open("krypt");
      r.onsuccess = () => resolve(r.result);
    });
    const blobs = await new Promise((resolve) => {
      const req = db.transaction("files").objectStore("files").getAll();
      req.onsuccess = () => resolve(req.result);
    });
    return blobs.some((b) => b.type === "audio/webm");
  });
  const leaked = await alice.page.evaluate(async () => {
    const db = await new Promise((resolve) => {
      const r = indexedDB.open("krypt");
      r.onsuccess = () => resolve(r.result);
    });
    const blobs = await new Promise((resolve) => {
      const req = db.transaction("files").objectStore("files").getAll();
      req.onsuccess = () => resolve(req.result);
    });
    const voice = blobs.find((b) => b.type === "audio/webm");
    const text = new TextDecoder("latin1").decode(await voice.arrayBuffer());
    return ["Chrome", "Chromium", "QTmuxingApp"].filter((name) => text.includes(name));
  });
  if (leaked.length > 0) throw new Error(`the voice message still names ${leaked}`);
  await alice.page.locator('.pane-chat .voice button[aria-label="Play voice message"]').click();
  await alice.page.waitForSelector(".pane-chat .voice.playing");
  await shot(alice.page, "3d-voice");
});

await step("alice mutes the chat, archives it, and a message from bob brings it back", async () => {
  const info = async () => {
    await alice.page.locator('button[aria-label="Conversation"]').click();
    await alice.page.waitForSelector(".sheet[open]");
  };
  await info();
  const notifications = (label) =>
    alice.page.$$eval('.sheet[open] [role="radiogroup"][aria-label="Notifications"] [role="radio"]', (bs, label) => bs.find((b) => b.textContent === label).click(), label);
  await notifications("Off");
  await alice.page.waitForSelector(".sheet[open] ::-p-text(Muted)");
  await alice.page.keyboard.press("Escape");
  await back(alice.page);
  await alice.page.waitForSelector('.list-item svg[aria-label="Muted"]');
  await alice.page.locator(".list-item").click();
  await info();
  await notifications("On");
  await alice.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Archive chat").click());
  await alice.page.waitForSelector("::-p-text(Archived (1))");
  if (await alice.page.$('.list-item svg[aria-label="Muted"]')) throw new Error("still muted");
  const listed = await alice.page.$$eval(".pane-list ul.list:not(.requests-list) .list-item", (items) => items.length);
  if (listed !== 0) throw new Error(`${listed} chats listed after archiving the only one`);
  await bob.page.locator(".composer textarea").fill("anyone there?");
  await bob.page.keyboard.press("Enter");
  await alice.page.waitForFunction(() => !document.body.textContent.includes("Archived (1)"));
  await alice.page.waitForSelector(".pane-list .list-item ::-p-text(anyone there?)").catch(async () => {
    throw new Error(`list shows: ${await alice.page.$eval(".pane-list", (e) => e.innerText.replace(/\s+/g, " "))}`);
  });
});

await step("search finds a message and opens the chat at it", async () => {
  await alice.page.locator('button[aria-label="Search"]').click();
  await alice.page.locator(".search-input").fill("NOON");
  await alice.page.waitForSelector(".search-hit mark::-p-text(noon)");
  await alice.page.locator(".search-hit").click();
  await alice.page.waitForSelector(".pane-chat article.msg.flash ::-p-text(see you at noon)");
});

/** What a device holds in its files store: each file's type, and whether
 * any of the fixture's metadata (all marked KRYPTLEAK) or GPS survived. */
const storedFiles = (page) =>
  page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const r = indexedDB.open("krypt");
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    const blobs = await new Promise((resolve) => {
      const r = db.transaction("files").objectStore("files").getAll();
      r.onsuccess = () => resolve(r.result);
    });
    db.close();
    return Promise.all(
      blobs.map(async (blob) => {
        const bytes = new Uint8Array(await blob.arrayBuffer());
        const text = new TextDecoder("latin1").decode(bytes);
        // Before the image data: the APP1 (EXIF/XMP) segments that remain.
        const app1 = [];
        for (let i = 2; i + 3 < bytes.length && bytes[i] === 0xff && bytes[i + 1] !== 0xda; ) {
          const length = (bytes[i + 2] << 8) | bytes[i + 3];
          if (bytes[i + 1] === 0xe1) app1.push(length);
          i += 2 + length;
        }
        return { type: blob.type, size: blob.size, leak: text.includes("KRYPTLEAK"), app1 };
      }),
    );
  });

await step("alice sends a photo; its location and camera never leave her phone", async () => {
  const input = await alice.page.$(".composer input[type=file]");
  await input.uploadFile(new URL("./fixtures/photo.jpg", import.meta.url).pathname);
  // Bob's copy downloads by itself and shows upright (orientation kept).
  const image = await bob.page.waitForSelector('.msg-file[data-state="ready"] img[src^="blob:"]');
  await bob.page.waitForFunction(
    () => {
      const img = document.querySelector('.msg-file[data-state="ready"] img');
      return img?.complete && img.naturalWidth > 0 && img.naturalWidth < img.naturalHeight;
    },
    { timeout },
  );
  const [received] = (await storedFiles(bob.page)).filter((f) => f.type === "image/jpeg");
  if (!received) throw new Error("bob has no stored photo");
  if (received.leak) throw new Error("metadata reached bob");
  if (received.app1.some((length) => length > 64)) throw new Error(`EXIF segments left: ${received.app1}`);
  const sent = (await storedFiles(alice.page)).filter((f) => f.type === "image/jpeg");
  if (sent.length !== 1 || sent[0].leak) throw new Error("alice keeps the cleaned copy only");
  await alice.page.waitForFunction(() => [...document.querySelectorAll(".msg.mine .msg-state")].at(-1)?.textContent === "Sent");
  await image.click();
  await bob.page.waitForSelector('dialog.viewer[open] img[src^="blob:"]');
  await shot(bob.page, "4-photo-viewer");
  await bob.page.keyboard.press("Escape");
});

await step("a web page sent as a file is saved, never opened", async () => {
  const input = await alice.page.$(".composer input[type=file]");
  await input.uploadFile(new URL("./fixtures/page.html", import.meta.url).pathname);
  await bob.page.waitForSelector("::-p-text(page.html)");
  await bob.page.locator('button[aria-label="Download page.html"]').click();
  const link = await bob.page.waitForSelector('a[aria-label="Save page.html"]');
  const download = await link.evaluate((a) => a.getAttribute("download"));
  if (download !== "page.html") throw new Error(`saves as ${download}`);
  const stored = await storedFiles(bob.page);
  if (!stored.some((f) => f.type === "application/octet-stream" && f.size > 0)) throw new Error("not stored inert");
  if ((await bob.page.title()) === "pwned") throw new Error("the page ran");
  await shot(bob.page, "5-files");
});

/** Whether a page's call shows the other side's video, playing. */
const seesVideo = (page) =>
  page.waitForFunction(() => {
    const video = document.querySelector(".call-remote");
    return video && video.videoWidth > 0 && video.currentTime > 0.5;
  });

/** The call's videos keep playing, uninterrupted, across several rounds of
 * connection stats: no element is replaced and none restarts (a black flash). */
async function steadyVideo(pages) {
  const mark = (page) =>
    page.evaluate(() => {
      window.restarts = 0;
      for (const video of document.querySelectorAll(".call video")) {
        video.dataset.steady = "1";
        video.addEventListener("emptied", () => window.restarts++);
      }
      return document.querySelectorAll(".call video").length;
    });
  const counts = await Promise.all(pages.map(mark));
  await new Promise((resolve) => setTimeout(resolve, 5_000));
  for (const [i, page] of pages.entries()) {
    const [kept, restarts] = await page.evaluate(() => [
      document.querySelectorAll('.call video[data-steady="1"]').length,
      window.restarts,
    ]);
    if (kept !== counts[i] || restarts !== 0) throw new Error(`videos: ${counts[i] - kept} of ${counts[i]} replaced, ${restarts} restarted`);
  }
}

await step("bob video-calls alice; they see and hear each other, end to end", async () => {
  await bob.page.locator('button[aria-label="Video call"]').click();
  await alice.page.waitForSelector('.call[data-call-state="incoming"]');
  await shot(alice.page, "6-call-incoming");
  await alice.page.locator('button[aria-label="Accept"]').click();
  for (const d of [alice, bob]) {
    await d.page.waitForSelector('.call[data-call-state="connected"]');
    await seesVideo(d.page);
    const audio = await d.page.$eval(".call-remote", (v) => v.srcObject.getAudioTracks().filter((t) => t.readyState === "live").length);
    if (audio !== 1) throw new Error(`${d.name} hears ${audio} audio tracks`);
  }
  await bob.page.waitForFunction(() => /Direct|Relayed/.test(document.querySelector(".call-path")?.textContent ?? ""));
  const secure = await text(bob.page, ".call-secure");
  if (!secure.includes("End-to-end encrypted")) throw new Error(`call shows ${secure}`);
  await shot(bob.page, "7-call");
});

await step("call video plays steadily, never flashing black", async () => {
  await steadyVideo([alice.page, bob.page]);
});

await step("relay credentials go only to members", async () => {
  const status = await bob.page.evaluate(async () => {
    const conversation = "00".repeat(16);
    const forged = "00".repeat(8) + "11".repeat(16);
    const missing = await fetch(`/v1/turn/${conversation}`, { method: "POST" });
    const wrong = await fetch(`/v1/turn/${conversation}`, { method: "POST", headers: { "krypt-auth": forged } });
    return [missing.status, wrong.status];
  });
  if (status[0] !== 401 || status[1] !== 404) throw new Error(`statuses ${status}`);
});

await step("alice mutes and turns off her camera; bob hangs up and both see the call", async () => {
  await alice.page.locator('button[aria-label="Mute"]').click();
  await alice.page.waitForSelector('button[aria-label="Unmute"][aria-pressed="true"]');
  await alice.page.locator('button[aria-label="Turn camera off"]').click();
  await alice.page.waitForSelector('button[aria-label="Turn camera on"]');
  await bob.page.locator('button[aria-label="End call"]').click();
  for (const d of [alice, bob]) {
    await d.page.waitForFunction(() => !document.querySelector(".call"), { timeout: 10_000 });
    await d.page.waitForFunction(() =>
      [...document.querySelectorAll(".system")].some((e) => /^Video call · \d+:\d\d$/.test(e.textContent ?? "")),
    );
  }
});

await step("alice calls bob, who declines", async () => {
  await alice.page.locator('button[aria-label="Voice call"]').click();
  await bob.page.waitForSelector('.call[data-call-state="incoming"]');
  await bob.page.locator('button[aria-label="Decline"]').click();
  await alice.page.waitForFunction(() => document.querySelector(".call-status")?.textContent === "Declined" || !document.querySelector(".call"));
  await alice.page.waitForSelector("::-p-text(Voice call declined)");
  await bob.page.waitForSelector("::-p-text(Declined voice call)");
  for (const d of [alice, bob]) await d.page.waitForFunction(() => !document.querySelector(".call"), { timeout: 10_000 });
});

await step("their safety numbers match", async () => {
  const number = async (page) => {
    await page.locator('button[aria-label="Conversation"]').click();
    await page.locator(".chip").click();
    const value = await text(page, ".safety");
    await page.keyboard.press("Escape");
    return value;
  };
  const [a, b] = [await number(alice.page), await number(bob.page)];
  if (a !== b || !/^\d{5}( \d{5}){11}$/.test(a)) throw new Error(`${a} vs ${b}`);
});

await step("a reload restores the device and its history", async () => {
  const before = await alice.page.$$eval(".msg", (m) => m.length);
  await alice.page.reload();
  await alice.page.locator(".list-item").click();
  await alice.page.waitForSelector("::-p-text(hello alice)");
  const after = await alice.page.$$eval(".msg", (m) => m.length);
  if (after !== before) throw new Error(`${before} messages before, ${after} after`);
  await bob.page.locator(".composer textarea").fill("still there?");
  await bob.page.keyboard.press("Enter");
  await alice.page.waitForSelector("::-p-text(still there?)");
});

await step("a second tab waits for the first", async () => {
  const second = await alice.context.newPage();
  await second.goto(url);
  await second.waitForSelector("::-p-text(krypt is open in another tab)");
  await alice.page.close();
  await second.waitForSelector(".list-item");
  alice.page = second;
});

/** Opens the first message request on alice's list. */
async function openRequest(page) {
  await page.waitForSelector(".requests");
  if ((await page.$eval(".requests", (b) => b.getAttribute("aria-expanded"))) !== "true") await page.locator(".requests").click();
  await page.locator(".requests-list .list-item").click();
}

/** Clicks the choice labelled exactly `label` in an open sheet. */
const choose = (page, label) =>
  page.$$eval('.sheet [role="radio"]', (buttons, label) => buttons.find((b) => b.textContent === label).click(), label);

/** Past the first-launch tour, to the identity it made. */
async function skipTour(page) {
  await page.locator("::-p-text(Skip)").click();
  await page.waitForSelector('.tour-end[data-active="true"]');
}

/** A new device, past onboarding. */
async function stranger(name) {
  const d = await device(name);
  await skipTour(d.page);
  await click(d.page, "Continue");
  return d;
}

/** `d` starts a chat with alice's card and says something. */
async function writeToAlice(d, text) {
  await click(d.page, "New chat");
  await d.page.locator(".sheet textarea").fill(aliceCard);
  await click(d.page, "Start chat");
  await d.page.waitForSelector(".pane-chat");
  await d.page.locator(".composer textarea").fill(text);
  await d.page.keyboard.press("Enter");
}

await step("alice turns on disappearing messages; a message disappears once seen", async () => {
  await alice.page.locator(".list-item").click();
  await alice.page.locator('button[aria-label="Conversation"]').click();
  await choose(alice.page, "5 minutes");
  await alice.page.keyboard.press("Escape");
  for (const d of [alice, bob]) await d.page.waitForSelector("::-p-text(5 minutes after they're seen)");
  await bob.page.waitForSelector(".status-timer");
  await bob.page.locator(".composer textarea").fill("this will vanish");
  await bob.page.keyboard.press("Enter");
  await alice.page.waitForSelector("::-p-text(this will vanish)");
  // Seeing it started its clock. Wind the clock forward and restart: it is gone.
  const due = await alice.page.waitForFunction(() =>
    new Promise((resolve) => {
      const open = indexedDB.open("krypt");
      open.onsuccess = () => {
        const store = open.result.transaction("messages", "readwrite").objectStore("messages");
        const all = store.getAll();
        all.onsuccess = () => {
          const row = all.result.find((r) => r.text === "this will vanish");
          if (!row?.deleteAt || row.expires !== 300) return resolve(false);
          store.put({ ...row, deleteAt: Date.now() - 1 }).onsuccess = () => resolve(true);
        };
      };
    }),
  );
  if (!(await due.jsonValue())) throw new Error("no clock");
  await alice.page.reload();
  await alice.page.locator(".list-item").click();
  await alice.page.waitForSelector("::-p-text(5 minutes after they're seen)");
  await alice.page.waitForFunction(() => !document.body.textContent.includes("this will vanish"));
  await alice.page.locator('button[aria-label="Conversation"]').click();
  await choose(alice.page, "Off");
  await alice.page.keyboard.press("Escape");
  await bob.page.waitForSelector("::-p-text(turned off disappearing messages)");
});

await step("a stranger's chat waits as a request, can't ring, and blocking ends it", async () => {
  const carol = await stranger("carol");
  await writeToAlice(carol, "hi, we haven't met");
  await back(alice.page);
  await openRequest(alice.page);
  await alice.page.waitForSelector("::-p-text(hi, we haven't met)");
  await alice.page.waitForSelector(".request-bar");
  await carol.page.locator('button[aria-label="Voice call"]').click();
  await alice.page.waitForSelector("::-p-text(Missed voice call)");
  if (await alice.page.$(".call")) throw new Error("a request rang");
  await carol.page.locator('button[aria-label="End call"]').click();
  await alice.page.$$eval(".request-bar button", (bs) => bs.find((b) => b.textContent === "Block").click());
  await alice.page.waitForFunction(() => !document.querySelector(".requests"));
  await carol.page.locator(".composer textarea").fill("are you there?");
  await carol.page.keyboard.press("Enter");
  await new Promise((r) => setTimeout(r, 2_000));
  if (await alice.page.$(".requests")) throw new Error("a blocked stranger got through");
  await carol.context.close();
});

await step("blocking from the conversation's info ends it", async () => {
  const dave = await stranger("dave");
  await writeToAlice(dave, "buy cheap stuff now");
  await openRequest(alice.page);
  await alice.page.waitForSelector("::-p-text(buy cheap stuff now)");
  await alice.page.locator('button[aria-label="Conversation"]').click();
  await alice.page.$$eval(".sheet button", (bs) => bs.find((b) => b.textContent.startsWith("Block") && b.closest(".sheet[open]")).click());
  await alice.page.waitForFunction(() => !document.querySelector(".requests"));
  await dave.context.close();
});

/** A passkey authenticator for a page (Chrome's virtual one, with PRF). */
async function authenticator(page) {
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  return cdp;
}

const settings = async (page) => {
  await back(page);
  await page.locator('button[aria-label="Settings"]').click();
};
/** One page of Settings, by its title in the menu. */
const settingsPage = async (page, title) => {
  await settings(page);
  await page.$$eval(".settings-menu .headline", (es, title) => es.find((e) => e.textContent === title).click(), title);
  await page.waitForSelector(`.pane-settings .bar .title::-p-text(${title})`);
};

await step("alice links a second device; it joins her chats and speaks as her", async () => {
  const laptop = await device("laptop");
  await skipTour(laptop.page);
  await click(laptop.page, "Link to my other device");
  const code = (await laptop.page.waitForSelector(".sheet[open] .card-text").then((e) => e.evaluate((n) => n.textContent))).trim();
  if (!/^krypt-link2:[a-z2-7]{52}$/.test(code)) throw new Error(`code ${code}`);
  await settingsPage(alice.page, "Devices");
  await click(alice.page, "Link a new device");
  await alice.page.locator(".sheet[open] textarea").fill(code);
  await alice.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Link").click());
  // The laptop shows the identity it would join, and it is alice's.
  const shown = await laptop.page.waitForSelector(".sheet[open] .fingerprint").then((e) => e.evaluate((n) => n.textContent));
  const hers = await alice.page.$eval(".sheet[open] .fingerprint", (n) => n.textContent);
  if (!shown || shown !== hers) throw new Error(`fingerprints ${shown} / ${hers}`);
  await laptop.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "It matches").click());
  await alice.page.waitForSelector("::-p-text(Linked. It is joining your chats.)");
  await alice.page.keyboard.press("Escape");
  // A code works once: its key is gone after the first use.
  await click(alice.page, "Link a new device");
  await alice.page.locator(".sheet[open] textarea").fill(code);
  await alice.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Link").click());
  await alice.page.waitForSelector("::-p-text(That code was used already)");
  await alice.page.keyboard.press("Escape");
  // The laptop is alice now: same fingerprint, and her chat with bob.
  await laptop.page.waitForSelector(".list-item", { timeout: 30_000 });
  const fingerprints = await Promise.all([alice, laptop].map((d) => d.page.evaluate(async () => {
    const button = [...document.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Settings");
    button.click();
    await new Promise((r) => setTimeout(r, 300));
    const f = document.querySelector(".fingerprint")?.textContent;
    document.querySelector('button[aria-label="Back"]')?.click();
    return f;
  })));
  if (!fingerprints[0] || fingerprints[0] !== fingerprints[1]) throw new Error(`fingerprints ${fingerprints}`);
  await laptop.page.locator(".list-item").click();
  await bob.page.locator(".composer textarea").fill("hello both of you");
  await bob.page.keyboard.press("Enter");
  await laptop.page.waitForSelector("::-p-text(hello both of you)");
  await alice.page.locator(".list-item").click();
  await alice.page.waitForSelector("::-p-text(hello both of you)");
  await laptop.page.locator(".composer textarea").fill("typed on the laptop");
  await laptop.page.keyboard.press("Enter");
  await bob.page.waitForSelector("::-p-text(typed on the laptop)");
  await alice.page.waitForSelector("::-p-text(typed on the laptop)");
  await shot(laptop.page, "8-linked-device");
  await laptop.context.close();
});

const erinHandle = `erin_${Math.random().toString(36).slice(2, 10)}`;
let erin;

await step("erin claims an @handle with a passkey; frank finds her by it", async () => {
  erin = await stranger("erin");
  await authenticator(erin.page);
  await settingsPage(erin.page, "Account and backup");
  await erin.page.locator('.settings input[placeholder="@name"]').fill(`@${erinHandle}`);
  await click(erin.page, "Claim with a passkey");
  await erin.page.waitForSelector(`::-p-text(@${erinHandle})`);
  await erin.page.waitForSelector("::-p-text(Backed up)");
  const frank = await stranger("frank");
  await click(frank.page, "New chat");
  await frank.page.locator(".sheet textarea").fill(`@${erinHandle}`);
  await click(frank.page, "Start chat");
  await frank.page.waitForSelector(".pane-chat");
  await frank.page.locator(".composer textarea").fill("found you by your handle");
  await frank.page.keyboard.press("Enter");
  await back(erin.page);
  await openRequest(erin.page);
  await erin.page.waitForSelector("::-p-text(found you by your handle)");
  const accepted = await erin.page.evaluate(() => Date.now());
  await erin.page.$$eval(".request-bar button", (bs) => bs.find((b) => b.textContent === "Accept").click());
  // The backup follows: frank is in it.
  await erin.page.waitForFunction(
    (since) => JSON.parse(localStorage.getItem("krypt.handle") ?? "{}").backedUpAt > since,
    { timeout: 15_000 },
    accepted,
  );
  erin.frank = frank;
});

await step("erin loses her device and restores it from the passkey", async () => {
  await settings(erin.page);
  const before = await text(erin.page, ".fingerprint");
  // Burning destroys everything on the device, as losing it would.
  await settingsPage(erin.page, "Burn this identity");
  const hold = await erin.page.waitForSelector(".hold");
  await hold.scrollIntoView();
  const box = await hold.boundingBox();
  await erin.page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  const state = () =>
    erin.page.$eval(".hold", (b) => ({
      phase: b.dataset.phase,
      progress: parseFloat(b.style.getPropertyValue("--progress")),
      label: b.textContent,
    }));
  // Letting go early: the bar fills part way, then drains; nothing burns.
  await erin.page.mouse.down();
  await new Promise((resolve) => setTimeout(resolve, 900));
  const holding = await state();
  if (holding.phase !== "holding" || !(holding.progress > 0.3 && holding.progress < 0.7) || holding.label !== "Keep holding") {
    throw new Error(`holding: ${JSON.stringify(holding)}`);
  }
  await erin.page.mouse.up();
  await erin.page.waitForFunction(() => document.querySelector(".hold")?.dataset.phase === "idle");
  if ((await state()).label !== "Hold to burn") throw new Error("not reset after letting go");
  // Holding to the end burns it, and krypt starts afresh (often before the
  // full bar could be looked at: the page reloads at once).
  await erin.page.mouse.down();
  await erin.page.waitForSelector("::-p-text(Welcome to krypt)", { timeout: 15_000 });
  await erin.page.mouse.up();
  await skipTour(erin.page);
  await click(erin.page, "Restore from a passkey");
  await erin.page.locator('.sheet[open] input[placeholder="@name"]').fill(`@${erinHandle}`);
  await erin.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Restore").click());
  await erin.page.waitForSelector(".pane-list", { timeout: 30_000 });
  await erin.page.locator('button[aria-label="Settings"]').click();
  const after = await text(erin.page, ".fingerprint");
  if (after !== before) throw new Error(`restored ${after}, was ${before}`);
  await erin.page.waitForSelector(`::-p-text(@${erinHandle})`);
  await erin.page.locator('button[aria-label="Back"]').click();
  // Frank reaches her again by her handle, and she knows him: no request.
  const frank = erin.frank;
  await back(frank.page);
  await frank.page.locator('button[aria-label="New chat"]').click();
  await frank.page.locator(".sheet textarea").fill(`@${erinHandle}`);
  await click(frank.page, "Start chat");
  await frank.page.waitForSelector(".pane-chat");
  await frank.page.locator(".composer textarea").fill("is this your new phone?");
  await frank.page.keyboard.press("Enter");
  await erin.page.waitForSelector(".list-item");
  if (await erin.page.$(".requests")) throw new Error("her restored contact came as a request");
  await erin.page.locator(".list-item").click();
  await erin.page.waitForSelector("::-p-text(is this your new phone?)");
  await frank.context.close();
  await erin.context.close();
});

/** A device's own card, from its card sheet. */
async function cardOf(d) {
  await back(d.page);
  await d.page.locator('button[aria-label="My card"]').click();
  const card = (await d.page.waitForSelector(".sheet[open] .card-text").then((e) => e.evaluate((n) => n.textContent))).trim();
  await d.page.keyboard.press("Escape");
  return card;
}

/** Whether a call screen shows `n` other people's video, playing. */
const seesVideos = (page, n) =>
  page.waitForFunction(
    (n) => {
      const videos = [...document.querySelectorAll(".call-tile video")];
      return videos.length === n && videos.every((v) => v.videoWidth > 0 && v.currentTime > 0.5);
    },
    { timeout: 30_000 },
    n,
  );

let gina, hal, ivy;

const newChat = (page) => page.locator('::-p-aria([name="New chat"][role="button"])').click();

await step("a group is made only from people you're connected with", async () => {
  [gina, hal, ivy] = await Promise.all(["gina", "hal", "ivy"].map(stranger));
  // Nobody yet: no way to add strangers, only a pointer to start a chat.
  await newChat(gina.page);
  await choose(gina.page, "New group");
  await gina.page.waitForSelector("::-p-text(Groups are made from people you're already connected with)");
  const fields = await gina.page.$$eval(".sheet[open] textarea, .sheet[open] input", (fs) => fs.filter((f) => f.offsetParent !== null).length);
  if (fields !== 0) throw new Error(`${fields} fields with nobody to add`);
  await gina.page.keyboard.press("Escape");
  // Gina connects with hal and ivy, one to one.
  const cards = await Promise.all([hal, ivy].map(cardOf));
  for (const [i, d] of [hal, ivy].entries()) {
    await back(gina.page);
    await newChat(gina.page);
    await gina.page.locator(".sheet[open] textarea").fill(cards[i]);
    await click(gina.page, "Start chat");
    await gina.page.locator(".composer textarea").fill("hi!");
    await gina.page.keyboard.press("Enter");
    await openRequest(d.page);
    await d.page.$$eval(".request-bar button", (bs) => bs.find((b) => b.textContent === "Accept").click());
    await d.page.waitForSelector(".composer textarea");
  }
});

await step("gina names a group with hal and ivy; everyone sees its name", async () => {
  await back(gina.page);
  await newChat(gina.page);
  await choose(gina.page, "New group");
  const people = await gina.page.$$eval(".sheet[open] .pick-list li", (items) => items.length);
  if (people !== 2) throw new Error(`${people} people to pick`);
  await gina.page.locator('.sheet[open] input[placeholder="Optional"]').fill("Weekend trip");
  for (const box of await gina.page.$$(".sheet[open] .pick-list input[type=checkbox]")) await box.click();
  await gina.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Create group with 2 people").click());
  await gina.page.waitForSelector(".bar-title::-p-text(Weekend trip)");
  for (const d of [hal, ivy]) {
    await back(d.page);
    await d.page.locator(".list-item::-p-text(Weekend trip)").click();
    await d.page.waitForSelector(".bar-title::-p-text(Weekend trip)");
    await d.page.waitForSelector(".composer textarea");
  }
  await gina.page.locator(".composer textarea").fill("who's in?");
  await gina.page.keyboard.press("Enter");
  for (const d of [hal, ivy]) await d.page.waitForSelector("::-p-text(who's in?)");
  await shot(hal.page, "9-group");
});

await step("gina is the group's admin; she keeps adding people to admins, then makes hal one", async () => {
  const info = async (page) => {
    await page.locator('button[aria-label="Conversation"]').click();
    await page.waitForSelector(".sheet[open]");
  };
  const admins = (page) =>
    page.$$eval(".sheet[open] ul.list:not(.pick-list) li.member", (items) =>
      items.filter((li) => li.querySelector(".admin-chip")).map((li) => li.querySelector(".headline, input")?.value || li.querySelector(".headline")?.textContent),
    );
  await info(gina.page);
  const first = await admins(gina.page);
  if (first.length !== 1 || first[0] !== "You") throw new Error(`admins ${first}`);
  await gina.page.$$eval('.sheet[open] [role="radiogroup"][aria-label="Who can add people"] [role="radio"]', (bs) =>
    bs.find((b) => b.textContent === "Only admins").click(),
  );
  await hal.page.waitForSelector("::-p-text(only admins can add people now)");
  await info(hal.page);
  await hal.page.waitForSelector(".sheet[open] ::-p-text(Only admins can change this.)");
  if (await hal.page.$(".sheet[open] ::-p-text(Add someone you're connected with)")) throw new Error("hal may add people");
  await hal.page.keyboard.press("Escape");
  // Gina makes someone an admin; now they may.
  await gina.page.$$eval(".sheet[open] .member .icon-btn[aria-label^='Manage']", (bs) => bs[0].click());
  await gina.page.$$eval(".sheet[open] .member-actions button", (bs) => bs.find((b) => b.textContent === "Make admin").click());
  await gina.page.keyboard.press("Escape");
  await Promise.any([hal, ivy].map((d) => d.page.waitForSelector("::-p-text(an admin.)")));
  // Whoever was made admin sees the controls open to them.
  const made = (await hal.page.$("::-p-text(made you an admin.)")) ? hal : ivy;
  await info(made.page);
  await made.page.waitForSelector(".sheet[open] ::-p-text(Add someone you're connected with)");
  await made.page.keyboard.press("Escape");
  await shot(made.page, "9b-admins");
});

await step("a group video call connects everyone to everyone", async () => {
  await gina.page.locator('button[aria-label="Video call"]').click();
  for (const d of [hal, ivy]) {
    await d.page.waitForSelector('.call[data-call-state="incoming"]');
    await d.page.locator('button[aria-label="Join"]').click();
  }
  for (const d of [gina, hal, ivy]) {
    await d.page.waitForSelector('.call[data-call-state="connected"]');
    await seesVideos(d.page, 2);
  }
  await steadyVideo([gina.page, hal.page, ivy.page]);
  await shot(gina.page, "10-group-call");
});

await step("one leaves the call and the others carry on; the last one out ends it", async () => {
  await ivy.page.locator('button[aria-label="End call"]').click();
  for (const d of [gina, hal]) await seesVideos(d.page, 1);
  await hal.page.locator('button[aria-label="End call"]').click();
  await gina.page.waitForFunction(() => !document.querySelector(".call"), { timeout: 15_000 });
  for (const d of [gina, hal, ivy]) {
    await d.page.waitForFunction(() => [...document.querySelectorAll(".system")].some((e) => /^Group video call · \d+:\d\d$/.test(e.textContent ?? "")));
  }
});

await step("someone leaves the group and the others see them go", async () => {
  await ivy.page.locator('button[aria-label="Conversation"]').click();
  await ivy.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Leave group").click());
  await ivy.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Leave").click());
  await ivy.page.waitForFunction(() => ![...document.querySelectorAll(".list-item")].some((e) => e.textContent.includes("Weekend trip")), {
    timeout: 30_000,
  });
  for (const d of [gina, hal]) await d.page.waitForSelector("::-p-text(left.)", { timeout: 30_000 });
  await gina.page.locator('button[aria-label="Conversation"]').click();
  const members = await gina.page.$$eval(".sheet[open] ul.list:not(.pick-list) li.member", (items) => items.length);
  if (members !== 2) throw new Error(`${members} members after one left`);
  await gina.page.keyboard.press("Escape");
  await ivy.context.close();
});

await step("someone with the invite link asks to join; an admin lets them in, and declines another", async () => {
  await gina.page.locator('button[aria-label="Conversation"]').click();
  await click(gina.page, "Turn on invite link");
  const link = await gina.page.waitForFunction(() => document.querySelector(".sheet[open] .invite-link")?.textContent);
  const joinUrl = await link.jsonValue();
  if (!/#join=[a-z2-7]{77}$/.test(joinUrl)) throw new Error(`link ${joinUrl}`);
  await gina.page.keyboard.press("Escape");
  await hal.page.waitForSelector("::-p-text(turned on the invite link.)");
  // Gina's device opens the group's requests log once the link is in.
  await new Promise((r) => setTimeout(r, 2_000));
  const ask = async (name, as) => {
    const d = await stranger(name);
    await d.page.goto(joinUrl.replace(/^https:\/\/[^/]+/, new URL(url).origin));
    await d.page.reload();
    await d.page.waitForSelector("::-p-text(Ask to join “Weekend trip”?)");
    await d.page.locator(".sheet[open] input").fill(as);
    await d.page.$$eval(".sheet[open] button", (bs) => bs.find((b) => b.textContent === "Ask to join").click());
    await d.page.waitForSelector("::-p-text(Asked. You'll be in the group)");
    await d.page.keyboard.press("Escape");
    await d.page.waitForSelector("::-p-text(Waiting for an admin of “Weekend trip”)");
    return d;
  };
  const jo = await ask("jo", "Jo");
  const kim = await ask("kim", "Kim");
  await gina.page.locator('button[aria-label="Conversation"]').click();
  await gina.page.waitForSelector(".sheet[open] .join-request ::-p-text(Jo)");
  await gina.page.waitForSelector(".sheet[open] .join-request ::-p-text(Kim)");
  await shot(gina.page, "9c-join-requests");
  const answer = (who, label) =>
    gina.page.$$eval(
      ".sheet[open] .join-request",
      (items, [who, label]) =>
        items
          .find((li) => li.textContent.includes(who))
          .querySelectorAll("button")
          .forEach((b) => b.textContent === label && b.click()),
      [who, label],
    );
  await answer("Kim", "Decline");
  await answer("Jo", "Let in");
  await gina.page.waitForFunction(() => !document.querySelector(".sheet[open] .join-request"));
  await gina.page.keyboard.press("Escape");
  // Jo is in, and the group is no request to her.
  await jo.page.locator(".list-item::-p-text(Weekend trip)").click();
  await jo.page.waitForSelector(".composer textarea");
  if (await jo.page.$(".request-bar")) throw new Error("the group jo asked for came as a request");
  await jo.page.locator(".composer textarea").fill("thanks for having me");
  await jo.page.keyboard.press("Enter");
  for (const d of [gina, hal]) await d.page.waitForSelector("::-p-text(thanks for having me)");
  // Kim, declined, is still waiting and in nothing.
  await new Promise((r) => setTimeout(r, 2_000));
  if (await kim.page.$(".list-item")) throw new Error("kim got in");
  await kim.page.waitForSelector("::-p-text(Waiting for an admin)");
  for (const d of [gina, hal, jo, kim]) await d.context.close();
});

await step("a wakeup shows a content-free notification", async () => {
  const origin = new URL(url).origin;
  await bob.context.overridePermissions(origin, ["notifications"]);
  const page = bob.page;
  const scope = await page.evaluate(async () => (await navigator.serviceWorker.ready).active?.scriptURL);
  if (!scope?.endsWith("/sw.js")) throw new Error(`service worker ${scope}`);
  const cdp = await page.createCDPSession();
  const registration = new Promise((resolve) =>
    cdp.on("ServiceWorker.workerRegistrationUpdated", ({ registrations }) => {
      const r = registrations.find((r) => r.scopeURL.startsWith(origin));
      if (r) resolve(r.registrationId);
    }),
  );
  await cdp.send("ServiceWorker.enable");
  const registrationId = await registration;
  // No krypt window in front: the wakeup must become a notification.
  const away = await bob.context.newPage();
  await away.goto("about:blank");
  await away.bringToFront();
  await cdp.send("ServiceWorker.deliverPushMessage", { origin, registrationId, data: "" });
  await new Promise((r) => setTimeout(r, 1000));
  const shown = await page.evaluate(async () =>
    (await (await navigator.serviceWorker.ready).getNotifications()).map((n) => [n.title, n.body]),
  );
  await away.close();
  await page.bringToFront();
  if (shown.length !== 1 || shown[0][0] !== "krypt" || /hello|bob|alice/i.test(shown[0][1])) {
    throw new Error(`notifications ${JSON.stringify(shown)}`);
  }
});

await step("settings is a short menu: account first, burn last, back returns to it", async () => {
  await settings(bob.page);
  const entries = await bob.page.$$eval(".settings-menu .headline", (es) => es.map((e) => e.textContent));
  if (entries[0] !== "Account and backup" || entries.at(-1) !== "Burn this identity") throw new Error(`menu ${entries}`);
  const fits = await bob.page.$eval(".settings", (e) => e.scrollHeight <= e.clientHeight + 1);
  if (!fits) throw new Error("the menu needs scrolling");
  // Every icon is drawn, even when one appears on many rows.
  const blank = await bob.page.$$eval(".settings-menu svg", (svgs) => svgs.filter((s) => s.childElementCount === 0).length);
  if (blank > 0) throw new Error(`${blank} icons are blank`);
  await shot(bob.page, "4-settings-menu");
  await bob.page.$$eval(".settings-menu .headline", (es) => es.find((e) => e.textContent === "Privacy and safety").click());
  await bob.page.waitForSelector("::-p-text(Always relay calls)");
  await bob.page.evaluate(() => history.back());
  await bob.page.waitForSelector(".settings-menu");
  await back(bob.page);
  if ((await bob.page.$eval(".app", (e) => e.dataset.view)) !== "home") throw new Error("back did not reach the chats");
});

await step("the tour can be read again from Settings", async () => {
  await settingsPage(bob.page, "How krypt works");
  await bob.page.waitForSelector('.tour-page[data-active="true"] h1::-p-text(Welcome to krypt)');
  // Swiping works as well as Next.
  await bob.page.$eval(".tour-pages", (e) => e.scrollTo({ left: e.clientWidth }));
  await bob.page.waitForSelector('.tour-page[data-active="true"] h1::-p-text(Connect with your card)');
  await shot(bob.page, "11-tour");
  await bob.page.locator("::-p-text(Skip)").click();
  await bob.page.waitForSelector('.tour-end[data-active="true"] ::-p-text(That\'s krypt)');
  await bob.page.$$eval(".tour-end button", (bs) => bs.find((b) => b.textContent === "Done").click());
  await bob.page.waitForSelector(".settings-menu");
  await back(bob.page);
});

await step("settings offer notifications", async () => {
  await settingsPage(bob.page, "Notifications");
  await bob.page.waitForSelector("::-p-text(Notify me when krypt is closed)");
  await back(bob.page);
});

/** Phones zoom into a focused field under 16px; no field may be. */
async function fieldsAt16(page) {
  const small = await page.$$eval('input:not([type="checkbox"], [type="radio"]), textarea', (fields) =>
    fields.map((f) => [f.placeholder || f.className, parseFloat(getComputedStyle(f).fontSize)]).filter(([, size]) => size < 16),
  );
  if (small.length > 0) throw new Error(`fields under 16px: ${JSON.stringify(small)}`);
}

for (const theme of ["Swiss Mono", "Soft Expressive", "Obsidian Glass"]) {
  await step(`theme: ${theme}; no text field is small enough to zoom into`, async () => {
    await settingsPage(bob.page, "Appearance");
    await click(bob.page, theme);
    await shot(bob.page, `4-settings-${theme.split(" ")[0].toLowerCase()}`);
    await back(bob.page);
    await bob.page.locator('button[aria-label="New chat"]').click();
    await choose(bob.page, "New group");
    await bob.page.waitForSelector('.sheet[open] input[placeholder="Optional"]');
    await fieldsAt16(bob.page);
    await bob.page.keyboard.press("Escape");
    await bob.page.locator(".list-item").click();
    await bob.page.waitForSelector("::-p-text(still there?)");
    await bob.page.locator('button[aria-label="Conversation"]').click();
    await bob.page.waitForSelector(".sheet[open]");
    await fieldsAt16(bob.page);
    await bob.page.keyboard.press("Escape");
    await shot(bob.page, `5-chat-${theme.split(" ")[0].toLowerCase()}`);
  });
}

await step("the keyboard never zooms or pans the page; the chat fits above it", async () => {
  const page = bob.page;
  const zoom = await page.$eval('meta[name="viewport"]', (m) => m.content);
  if (!/maximum-scale=1\b/.test(zoom) || !/interactive-widget=resizes-content/.test(zoom)) throw new Error(`viewport ${zoom}`);
  await page.locator(".composer textarea").click();
  /** Where the header and composer are, against what is visible. */
  const layout = () =>
    page.evaluate(() => {
      const visual = window.visualViewport;
      const top = visual.offsetTop;
      const bottom = top + visual.height;
      const bar = document.querySelector(".pane-chat .bar").getBoundingClientRect();
      const composer = document.querySelector(".composer").getBoundingClientRect();
      return { top, bottom, bar: bar.top, composer: composer.bottom, scrolled: window.scrollY, focused: document.activeElement?.tagName };
    });
  const fits = (l, what) => {
    if (Math.abs(l.bar - l.top) > 1 || Math.abs(l.composer - l.bottom) > 1 || l.scrolled !== 0 || l.focused !== "TEXTAREA") {
      throw new Error(`${what}: ${JSON.stringify(l)}`);
    }
  };
  // Android: the page shrinks to the space above the keyboard.
  await page.setViewport({ width: 420, height: 520, deviceScaleFactor: 2 });
  await page.waitForFunction(() => document.querySelector(".composer").getBoundingClientRect().bottom <= 521);
  fits(await layout(), "page shrunk");
  await page.setViewport({ width: 420, height: 860, deviceScaleFactor: 2 });
  // Safari: the keyboard covers a full-height page and pans it to the field.
  for (const offsetTop of [0, 120]) {
    await page.evaluate((offsetTop) => {
      Object.defineProperty(window.visualViewport, "height", { configurable: true, get: () => 520 });
      Object.defineProperty(window.visualViewport, "offsetTop", { configurable: true, get: () => offsetTop });
      window.visualViewport.dispatchEvent(new Event("resize"));
    }, offsetTop);
    await page.waitForFunction((bottom) => Math.abs(document.querySelector(".composer").getBoundingClientRect().bottom - bottom) <= 1, {}, offsetTop + 520);
    fits(await layout(), `keyboard over the page, panned ${offsetTop}px`);
  }
  await page.evaluate(() => {
    delete window.visualViewport.height;
    delete window.visualViewport.offsetTop;
    window.visualViewport.dispatchEvent(new Event("resize"));
  });
  await page.waitForFunction(() => document.querySelector(".composer").getBoundingClientRect().bottom >= 859);
});

await step("back closes a sheet first, then leaves the chat", async () => {
  await bob.page.locator('button[aria-label="Conversation"]').click();
  await bob.page.waitForSelector(".sheet[open]");
  await bob.page.evaluate(() => history.back());
  await bob.page.waitForFunction(() => !document.querySelector(".sheet[open]"));
  if ((await bob.page.$eval(".app", (e) => e.dataset.view)) !== "chat") throw new Error("left the chat with the sheet");
  await bob.page.evaluate(() => history.back());
  await bob.page.waitForFunction(() => document.querySelector(".app")?.dataset.view === "home");
});

await browser.close();
console.log(failures.length === 0 ? "all passed" : `${failures.length} failed`);
process.exit(failures.length === 0 ? 0 : 1);
