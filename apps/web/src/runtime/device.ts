// The device: the Rust core (WebAssembly) driven one input at a time. Each
// input yields a step; its writes and the history it produced are committed
// to IndexedDB, and only then are its requests sent and its events shown.
// If storage ever fails, the device stops: acting on a step that is not
// durable could reuse encryption keys after a reload.

import init, {
  Device,
  fileLimits,
  fileParts,
  joinHeaderFrame,
  joinHeaderName,
  linkKeyDrop,
  LinkOffer,
  openPart,
  sealPart,
  type CallSignal,
  type KryptEvent,
  type SharedFile,
  type MessageRef,
  type Policy,
  type SignalKind,
  type Step,
} from "../core/krypt_wasm.js";
import { AUTO_DOWNLOAD_MAX, getPart, partUrl, putPart, shown, sleep, storedType } from "./files";
import { native } from "../app/platform";
import { LinkCodeUsed, put, take, takeNow } from "./link";
import { exchange, KIND_ACCEPTED, KIND_HEADER, Mailbox } from "./mailbox";
import { prepare, prepareVoice, safeName } from "./media";
import * as store from "./store";
import type { CallRecord, ChatRow, FileRow, Op, MessageRow, PersonRow, SystemEvent, UploadRow } from "./store";

const TICK_MS = 250;
const LOCK = "krypt-device";
/** The apps run one page, so a lock still held there belongs to a web view
 * Android has not torn down yet: after this long, the new page takes over
 * (and the old one, if it still runs, stops). */
const TAKEOVER_MS = 1_500;
const NOTHING: Step = { writes: [], requests: [], events: [] };
/** krypt_wire::limits: a voice message's size and length. */
const VOICE_SIZE_MAX = 8 * 1024 * 1024;
const VOICE_DURATION_MAX_MS = 15 * 60 * 1000;
const RETRY_MIN_MS = 1_000;
const RETRY_MAX_MS = 60_000;

export type { ChatRow, FileRow, MessageRow, PersonRow, KryptEvent };

/** How long leaving waits for the notice to be sent before deleting. */
const LEAVE_WAIT_MS = 30_000;
/** Messages one report carries at most. */
const REPORT_MESSAGES_MAX = 20;
const REPORT_TEXT_MAX = 2_000;
/** setTimeout's longest delay. */
const TIMEOUT_MAX_MS = 2 ** 31 - 1;

/** A file larger than krypt shares. */
export class FileTooLarge extends Error {}
/** The mailbox refused an upload: this device is no longer a member, or the
 * file is not acceptable. */
export class UploadRefused extends Error {}

/** Upload or download progress of a file, 0 to 1. */
export type Progress = (id: string, fraction: number | undefined) => void;

/** A call signal from another device: conversation, sender identity, its
 * device, the sender's clock and the signal. */
export type CallListener = (conversation: string, from: string, device: string, sentAtMs: number, signal: CallSignal) => void;
export type SignalListener = (conversation: string, from: string, device: string, kind: SignalKind) => void;

/** Relay credentials are reused for calls in the same conversation for this
 * long (they last much longer). */
const ICE_REUSE_MS = 10 * 60_000;
const STUN_ONLY: RTCIceServer[] = [{ urls: ["stun:stun.cloudflare.com:3478"] }];

export interface Committed {
  ops: Op[];
  events: KryptEvent[];
  /** Rows and chats a commit changed besides its own puts (reactions,
   * edits, deletions, read receipts). */
  changed?: store.Changed;
}

/** The id of the message a reference names, as this device stores it. */
export function refId(conversation: string, ref: MessageRef, myDevice: string): string {
  return `${conversation}:${ref.device === myDevice ? "me" : ref.device}:${ref.seq}`;
}

/** How every member names a stored message, or nothing for a row that is
 * not a message from a device (system rows, uploads in progress). */
export function refOf(row: MessageRow, myDevice: string): MessageRef | undefined {
  const match = /^[0-9a-f]+:(me|[0-9a-f]{64}):(\d+)$/.exec(row.id);
  if (!match || row.system) return undefined;
  return { device: match[1] === "me" ? myDevice : match[1]!, seq: Number(match[2]) };
}

let order = 0;
/** Display order: arrival time, unique within this session. */
function nextOrder(): number {
  order = Math.max(order + 1e-3, Date.now());
  return order;
}

const system = (conversation: string, event: SystemEvent, identities: string[] = [], extra: Partial<NonNullable<MessageRow["system"]>> = {}): Op => {
  const o = nextOrder();
  return {
    put: {
      id: `${conversation}:sys:${o}`,
      conversation,
      order: o,
      at: Date.now(),
      mine: false,
      text: "",
      system: { event, identities, ...extra },
    },
  };
};

/** History rows for a step's events. `known` says whether this device
 * knows an identity (a conversation with nobody it knows is a request). */
function opsFor(events: KryptEvent[], me: string, myDevice: string, known: (identity: string) => boolean): Op[] {
  const ops: Op[] = [];
  for (const e of events) {
    switch (e.type) {
      case "message": {
        // Calls leave their own history row, when they end; someone leaving
        // shows when the others remove them.
        if (e.call || e.left) break;
        const target = (ref: MessageRef) => refId(e.conversation, ref, myDevice);
        // Changes to other messages are checked against them when applied.
        if (e.react) {
          ops.push({ change: { react: { target: target(e.react.to), by: e.from, emoji: e.react.emoji } } });
          break;
        }
        if (e.edit) {
          ops.push({ change: { edit: { target: target(e.edit.to), by: e.from, me, text: e.edit.text, at: e.sentAtMs } } });
          break;
        }
        if (e.delete) {
          ops.push({ change: { erase: { target: target(e.delete), by: e.from, me, at: e.sentAtMs } } });
          break;
        }
        if (e.receipt) {
          // This identity's other devices say what they read; that is not news.
          if (e.from !== me) {
            const through = e.receipt.map((r): [string, number] => [r.device === myDevice ? "me" : r.device, r.seq]);
            ops.push({ read: { conversation: e.conversation, reader: e.from, through } });
          }
          break;
        }
        ops.push({
          once: true,
          put: {
            id: `${e.conversation}:${e.device}:${e.senderSeq}`,
            conversation: e.conversation,
            order: nextOrder(),
            at: e.sentAtMs,
            mine: false,
            from: e.from,
            text: e.text ?? "",
            // The sender's name for the file, cleaned before anything shows it.
            ...(e.file && { file: { ...e.file, name: safeName(e.file.name), state: "remote" as const } }),
            ...(e.replyTo && { replyTo: target(e.replyTo) }),
            ...(e.voice && { voice: { durationMs: e.voice.durationMs, waveform: [...e.voice.waveform] } }),
            ...(e.expiresAfterS > 0 && { expires: e.expiresAfterS }),
          },
        });
        break;
      }
      case "sent":
        ops.push({ sent: `${e.conversation}:me:${e.senderSeq}` });
        break;
      case "started":
        ops.push(system(e.conversation, e.type), { chat: { id: e.conversation, request: false } });
        break;
      case "removed":
        ops.push(system(e.conversation, e.type));
        break;
      case "joined":
        // A request unless whoever added this device is someone it knows
        // (who else is in the group does not matter: anyone can put a
        // stranger in a group with one of their contacts), or it answers
        // this device's own request through the group's link, whose
        // approving admin then becomes someone it knows.
        ops.push(system(e.conversation, "joined", e.members), {
          chat: {
            id: e.conversation,
            request: !e.viaLink && e.addedBy !== me && !known(e.addedBy),
            addedBy: e.addedBy,
            ...((e.viaLink || e.members.length > 2) && { group: true }),
          },
        });
        if (e.viaLink && e.addedBy !== me && !known(e.addedBy)) ops.push({ person: { identity: e.addedBy, verified: false } });
        break;
      case "membersAdded":
        ops.push(system(e.conversation, e.type, e.identities));
        break;
      case "membersRemoved":
        ops.push(system(e.conversation, e.type, e.identities, e.by ? { by: e.by } : {}));
        break;
      case "inviteFailed":
        ops.push(system(e.conversation, "inviteFailed", [e.identity]));
        break;
      case "undecryptable":
        ops.push(system(e.conversation, e.type));
        break;
      case "desync":
        ops.push(system(e.conversation, e.reason.startsWith("rules: ") ? "rulesBroken" : "desync"));
        break;
      case "refused":
        ops.push(system(e.conversation, "refused"));
        break;
      case "rules":
        ops.push(
          system(e.conversation, "rules", [e.by], {
            rules: { added: e.adminsAdded, removed: e.adminsRemoved, add: e.add, edit: e.edit, link: e.link },
          }),
        );
        break;
      case "timer":
        ops.push(system(e.conversation, "timer", [e.by], { seconds: e.seconds }));
        break;
      case "timerRefused":
        ops.push(system(e.conversation, "timerRefused"));
        break;
      case "renamed":
        ops.push(system(e.conversation, "renamed", [e.by], { name: e.name }));
        break;
      case "sealed":
        break;
    }
  }
  return ops;
}

export class Runtime {
  private queue: Promise<unknown> = Promise.resolve();
  private stopped = false;
  private timer?: ReturnType<typeof setInterval>;
  private mailbox: Mailbox;
  private followed = "";
  private listeners = new Set<(c: Committed) => void>();
  private progress = new Set<Progress>();
  private calls = new Set<CallListener>();
  private signals = new Set<SignalListener>();
  private connected = new Set<() => void>();
  /** Files moving right now, by id. */
  private moving = new Set<string>();
  private ice = new Map<string, { servers: Promise<RTCIceServer[]>; until: number }>();
  /** People this device knows (named, verified, or chatted with), and what
   * it decided about each conversation. */
  private known = new Set<string>();
  private chats = new Map<string, ChatRow>();
  private sweeping?: { at: number; timer: ReturnType<typeof setTimeout> };
  /** Resolves when this runtime stops, releasing the tab's device lock. */
  private release!: () => void;
  private released = new Promise<void>((resolve) => (this.release = resolve));
  /** How long the last relay credentials last, in seconds. */
  iceTtlS = 0;

  private constructor(
    private device: Device,
    readonly db: IDBDatabase,
    private mailboxBase: string,
    private onFatal: (error: unknown) => void,
  ) {
    this.mailbox = new Mailbox(
      mailboxBase,
      (frame) => void this.run((d, now) => ({ step: d.receive(now, frame) })),
      () => {
        void this.run((d, now) => ({ step: d.pollNow(now) }));
        for (const listener of this.connected) listener();
      },
    );
  }

  /** Waits for this browser's device lock (one tab at a time), then opens
   * or creates the device. `waiting` runs if another tab holds it. */
  static start(
    mailboxBase: string,
    waiting: () => void,
    onFatal: (error: unknown) => void,
    /** For a new device of an existing identity: its link payload. */
    linked?: Uint8Array,
  ): Promise<Runtime> {
    return new Promise((resolve, reject) => {
      let started: Runtime | undefined;
      const run = async () => {
        await init();
        const db = await store.open();
        const records = await store.loadCore(db);
        const now = Date.now();
        const device =
          records.length > 0 ? Device.restore(records, now) : linked ? Device.createLinked(linked, now) : Device.create(now);
        const runtime = new Runtime(device, db, mailboxBase, onFatal);
        started = runtime;
        for (const person of await store.people(db)) runtime.known.add(person.identity);
        for (const chat of await store.chats(db)) runtime.chats.set(chat.id, chat);
        await store.dropParked(db, now);
        await runtime.run(() => ({ step: device.takeStartup() }));
        void runtime.sweep();
        runtime.timer = setInterval(() => void runtime.run((d, now) => ({ step: d.tick(now) })), TICK_MS);
        for (const upload of await store.uploads(db)) void runtime.upload(upload);
        resolve(runtime);
        // Hold the lock for as long as this device runs.
        await runtime.released;
      };
      navigator.locks
        .request(LOCK, { ifAvailable: true }, async (lock) => {
          if (lock) return run();
          waiting();
          if (native) {
            await sleep(TAKEOVER_MS);
            return navigator.locks.request(LOCK, { steal: true }, run);
          }
          return navigator.locks.request(LOCK, run);
        })
        .catch((error: unknown) => {
          // Taken over by a newer page: stop at once, so two never write.
          if (!started) return reject(error);
          started.stop();
          onFatal(error);
        });
    });
  }

  onCommit(listener: (c: Committed) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onProgress(listener: Progress): () => void {
    this.progress.add(listener);
    return () => this.progress.delete(listener);
  }

  onCall(listener: CallListener): () => void {
    this.calls.add(listener);
    return () => this.calls.delete(listener);
  }

  /** Signals (typing, online) from the other members' devices. */
  onSignal(listener: SignalListener): () => void {
    this.signals.add(listener);
    return () => this.signals.delete(listener);
  }

  /** A log's socket (re)connected: signals sent before it opened were lost. */
  onConnected(listener: () => void): () => void {
    this.connected.add(listener);
    return () => this.connected.delete(listener);
  }

  /** Tells the members of a conversation connected right now that this
   * device is typing, stopped, online or offline. It stores nothing and
   * touches no state that is persisted, so it skips the queue; with the
   * conversation's socket down it is dropped. */
  signal(conversation: string, kind: SignalKind) {
    if (this.stopped) return;
    let step: Step;
    try {
      step = this.device.signal(Date.now(), conversation, kind);
    } catch {
      return;
    }
    for (const request of step.requests) this.mailbox.sendLive(request as Uint8Array<ArrayBuffer>);
  }

  private announce(committed: Committed) {
    for (const listener of this.listeners) listener(committed);
  }

  private report(id: string, fraction: number | undefined) {
    for (const listener of this.progress) listener(id, fraction);
  }

  /** Runs one input through the device: persist, then act. */
  run<T>(input: (device: Device, now: number) => { step: Step; ops?: Op[]; value?: T }): Promise<T | undefined> {
    const next = this.queue.then(async () => {
      if (this.stopped) throw new Error("the device has stopped");
      const { step, ops = [], value } = input(this.device, Date.now());
      const all = [...ops, ...opsFor(step.events, this.device.identity(), this.device.deviceId(), (i) => this.known.has(i))];
      // A message in an archived chat brings it back, unless it is muted.
      for (const op of [...all]) {
        if (!("put" in op) || op.put.mine || op.put.system) continue;
        const chat = this.chats.get(op.put.conversation);
        const muted = (this.device.mutedUntil(op.put.conversation) ?? 0) > Date.now();
        if (chat?.archived && !muted) all.push({ chat: { ...chat, archived: false } });
      }
      let changed: store.Changed | undefined;
      if (step.writes.length > 0 || all.length > 0) {
        try {
          changed = await store.commit(this.db, step.writes as [Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer> | null][], all);
        } catch (error) {
          this.stop();
          this.onFatal(error);
          throw error;
        }
      }
      for (const request of step.requests) this.mailbox.send(request as Uint8Array<ArrayBuffer>);
      const routes = this.device.routes();
      const key = routes.join(",");
      if (key !== this.followed) {
        this.followed = key;
        this.mailbox.follow(routes);
      }
      for (const op of all) {
        if ("person" in op) this.known.add(op.person.identity);
        else if ("chat" in op) this.chats.set(op.chat.id, op.chat);
        else if ("forget" in op) this.chats.delete(op.forget);
        else if ("put" in op && op.put.deleteAt !== undefined) this.sweepAt(op.put.deleteAt);
        else if ("shown" in op) this.sweepAt(op.deleteAt);
      }
      for (const chat of changed?.chats ?? []) this.chats.set(chat.id, chat);
      if (all.length > 0 || step.events.length > 0) this.announce({ ops: all, events: step.events, changed });
      for (const e of step.events) {
        if (e.type === "signal") for (const listener of this.signals) listener(e.conversation, e.from, e.device, e.kind);
        if (e.type !== "message" || !e.call) continue;
        for (const listener of this.calls) listener(e.conversation, e.from, e.device, e.sentAtMs, e.call);
      }
      for (const op of all) {
        if (!("put" in op)) continue;
        const file = op.put.file;
        // Photos, videos and voice messages download at once; not from
        // message requests (whatever they say they are).
        const inline = shown(file?.mediaType ?? "") !== "file" && !this.chats.get(op.put.conversation)?.request;
        if (file?.state === "remote" && inline && file.size <= AUTO_DOWNLOAD_MAX) {
          void this.download(op.put);
        }
      }
      return value;
    });
    this.queue = next.catch(() => {});
    return next;
  }

  get identity(): string {
    return this.device.identity();
  }

  /** This device's id (hex), as call signals address it. */
  get deviceId(): string {
    return this.device.deviceId();
  }

  get fingerprint(): string {
    return this.device.fingerprint();
  }

  get contactCard(): string {
    return this.device.contactCard();
  }

  get pushTarget(): string | undefined {
    return this.device.pushTarget;
  }

  async setPushTarget(endpoint: string | null): Promise<void> {
    await this.run((d, now) => ({ step: d.setPushTarget(now, endpoint ?? undefined) }));
  }

  conversations() {
    return this.device.conversations();
  }

  /** The person a card names, as this device knows them, with the card
   * (and a name, if one was given) added. */
  private async personFor(card: string, name?: string): Promise<Op[]> {
    const identity = cardIdentity(card);
    if (!identity) return [];
    const known = await store.person(this.db, identity);
    const person: PersonRow = { verified: false, ...known, identity, card };
    if (name) person.name = name;
    return [{ person }];
  }

  async startConversation(card: string, name?: string): Promise<string> {
    const ops = await this.personFor(card, name);
    const id = await this.run((d, now) => {
      const { conversation, step } = d.startConversation(now, card);
      return { step, ops, value: conversation };
    });
    return id!;
  }

  /** Starts a group with these people (cards), named `name`. */
  async startGroup(cards: string[], name: string): Promise<string> {
    const ops = (await Promise.all(cards.map((card) => this.personFor(card)))).flat();
    const id = await this.run((d, now) => {
      const { conversation, step } = d.startGroup(now, cards, name);
      return { step, ops, value: conversation };
    });
    return id!;
  }

  async rename(conversation: string, name: string): Promise<void> {
    await this.run((d, now) => ({ step: d.rename(now, conversation, name) }));
  }

  groupName(conversation: string): string {
    return this.device.groupName(conversation);
  }

  /** Everyone this device shares a conversation with, one card each. */
  knownContacts(): string[] {
    return this.device.knownContacts();
  }

  /** Leaves a group: tells the members (who remove this identity), then,
   * once that is sent, deletes the conversation here. */
  async leaveGroup(conversation: string): Promise<void> {
    const seq = await this.run((d, now) => {
      const { senderSeq, step } = d.leave(now, conversation);
      return { step, value: senderSeq };
    });
    const sent = `${conversation}:leave:${seq}`;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(done, LEAVE_WAIT_MS);
      const stop = this.onCommit(({ events }) => {
        if (events.some((e) => e.type === "sent" && `${e.conversation}:leave:${e.senderSeq}` === sent)) done();
      });
      function done() {
        clearTimeout(timer);
        stop();
        resolve();
      }
    });
    await this.deleteChat(conversation);
  }

  async invite(conversation: string, card: string, name?: string): Promise<void> {
    const ops = await this.personFor(card, name);
    await this.run((d, now) => ({ step: d.invite(now, conversation, card), ops }));
  }

  async send(conversation: string, text: string): Promise<void> {
    await this.run((d, now) => {
      const expires = d.timer(conversation);
      const { senderSeq, step } = d.send(now, conversation, text);
      const row: MessageRow = {
        id: `${conversation}:me:${senderSeq}`,
        conversation,
        order: nextOrder(),
        at: now,
        mine: true,
        text,
        state: "queued",
        // Own messages are shown as they are sent: their clock starts now.
        ...(expires > 0 && { expires, deleteAt: now + expires * 1000 }),
      };
      return { step, ops: [{ put: row }] };
    });
  }

  /** Answers `to` with `text`. */
  async reply(conversation: string, to: MessageRow, text: string): Promise<void> {
    const ref = refOf(to, this.deviceId);
    if (!ref) return this.send(conversation, text);
    await this.run((d, now) => {
      const expires = d.timer(conversation);
      const { senderSeq, step } = d.sendContent(now, conversation, { type: "reply", to: ref, text });
      const row: MessageRow = {
        id: `${conversation}:me:${senderSeq}`,
        conversation,
        order: nextOrder(),
        at: now,
        mine: true,
        text,
        replyTo: to.id,
        state: "queued",
        ...(expires > 0 && { expires, deleteAt: now + expires * 1000 }),
      };
      return { step, ops: [{ put: row }] };
    });
  }

  /** Reacts to a message with `emoji`, or takes the reaction back (""). */
  async react(conversation: string, row: MessageRow, emoji: string): Promise<void> {
    const ref = refOf(row, this.deviceId);
    if (!ref) return;
    const by = this.identity;
    await this.run((d, now) => ({
      step: d.sendContent(now, conversation, { type: "react", to: ref, emoji }).step,
      ops: [{ change: { react: { target: row.id, by, emoji } } }],
    }));
  }

  /** New text for one of this identity's own messages. */
  async edit(conversation: string, row: MessageRow, text: string): Promise<void> {
    const ref = refOf(row, this.deviceId);
    if (!ref) return;
    const me = this.identity;
    await this.run((d, now) => ({
      step: d.sendContent(now, conversation, { type: "edit", to: ref, text }).step,
      ops: [{ change: { edit: { target: row.id, by: me, me, text, at: now } } }],
    }));
  }

  /** Deletes one of this identity's own messages for everyone. */
  async deleteForEveryone(conversation: string, row: MessageRow): Promise<void> {
    const ref = refOf(row, this.deviceId);
    if (!ref) return;
    const me = this.identity;
    await this.run((d, now) => ({
      step: d.sendContent(now, conversation, { type: "delete", to: ref }).step,
      ops: [{ change: { erase: { target: row.id, by: me, me, at: now } } }],
    }));
  }

  /** The group's rules (undefined: a group from before admins). */
  policy(conversation: string): Policy | undefined {
    return this.device.policy(conversation) ?? undefined;
  }

  /** The group's admins now (everyone, before the group has rules). */
  admins(conversation: string): string[] {
    return this.device.admins(conversation);
  }

  async setPolicy(conversation: string, policy: Policy): Promise<void> {
    await this.run((d, now) => ({ step: d.setPolicy(now, conversation, policy) }));
  }

  /** Removes someone (all their devices) from a group. */
  async removeMember(conversation: string, identity: string): Promise<void> {
    await this.run((d, now) => ({ step: d.removeMember(now, conversation, identity) }));
  }

  /** What an invite link points at: its group's name, or why it does not
   * work. */
  async joinHeader(code: string): Promise<{ name: string; header: Uint8Array } | undefined> {
    const answer = await exchange(this.mailboxBase, joinHeaderFrame(code) as Uint8Array<ArrayBuffer>);
    if (answer?.kind !== KIND_HEADER) return undefined;
    try {
      return { name: joinHeaderName(code, answer.body), header: answer.body };
    } catch {
      return undefined;
    }
  }

  /** Asks to join a group with its link; resolves once the request is
   * left at the group's requests log. */
  async askToJoin(code: string, header: Uint8Array, name: string): Promise<boolean> {
    let frame: Uint8Array | undefined;
    await this.run((d, now) => {
      const asked = d.joinRequest(now, code, header, name);
      frame = asked.frame;
      return { step: asked.step };
    });
    if (!frame) return false;
    const answer = await exchange(this.mailboxBase, frame as Uint8Array<ArrayBuffer>);
    return answer?.kind === KIND_ACCEPTED;
  }

  /** Groups this device asked to join, still waiting for an admin. */
  pendingJoins(): string[] {
    return this.device.pendingJoins();
  }

  async approveJoin(conversation: string, id: string): Promise<void> {
    await this.run((d, now) => ({ step: d.approveJoin(now, conversation, id) }));
  }

  /** Mutes a conversation until `until` (ms; Infinity: until unmuted), or
   * unmutes it (undefined). */
  async mute(conversation: string, until: number | undefined): Promise<void> {
    await this.run((d, now) => ({ step: d.setMuted(now, conversation, until) }));
  }

  /** Until when a conversation is muted (Infinity: until unmuted). */
  mutedUntil(conversation: string): number | undefined {
    return this.device.mutedUntil(conversation) ?? undefined;
  }

  /** Archives a conversation on this device, or brings it back. */
  /** Remembers that a conversation is a group. */
  async markGroup(conversation: string): Promise<void> {
    const chat = this.chats.get(conversation) ?? { id: conversation, request: false };
    if (chat.group) return;
    await this.run(() => ({ step: NOTHING, ops: [{ chat: { ...chat, group: true } }] }));
  }

  async archive(conversation: string, archived: boolean): Promise<void> {
    const chat = this.chats.get(conversation) ?? { id: conversation, request: false };
    await this.run(() => ({ step: NOTHING, ops: [{ chat: { ...chat, archived } }] }));
  }

  /** Messages containing `query`, newest first (searched on this device). */
  search(query: string): Promise<MessageRow[]> {
    return store.search(this.db, query);
  }

  /** A stored message, by id. */
  message(id: string): Promise<MessageRow | undefined> {
    return store.message(this.db, id);
  }

  /** Deletes a message from this device only. */
  async deleteForMe(row: MessageRow): Promise<void> {
    const ops: Op[] = [{ del: row.id }];
    if (row.file) ops.push({ dropFile: row.file.id });
    await this.run(() => ({ step: NOTHING, ops }));
  }

  /** Tells the other members which of their messages were read: the newest
   * of each sender device among `rows`. Quiet: it wakes nobody. */
  async markRead(conversation: string, rows: MessageRow[]): Promise<void> {
    const me = this.identity;
    const newest = new Map<string, number>();
    for (const row of rows) {
      if (row.mine || !row.from || row.from === me) continue;
      const ref = refOf(row, this.deviceId);
      if (ref && ref.seq > (newest.get(ref.device) ?? 0)) newest.set(ref.device, ref.seq);
    }
    if (newest.size === 0) return;
    const through = [...newest].slice(0, 64).map(([device, seq]) => ({ device, seq }));
    await this.run((d, now) => ({ step: d.sendContent(now, conversation, { type: "receipt", through }).step }));
  }

  // ---- Requests, blocking and disappearing messages ----------------------

  /** Whether a conversation is a request: someone this device does not
   * know started it, and it has not been accepted. */
  isRequest(conversation: string): boolean {
    return this.chats.get(conversation)?.request ?? false;
  }

  /** Accepts a request: the person who started it (in a group, whoever
   * added this device) becomes someone this device knows; the group's
   * other members do not. */
  async accept(conversation: string, members: string[]): Promise<void> {
    const me = this.identity;
    const chat = this.chats.get(conversation) ?? { id: conversation, request: false };
    const others = members.filter((m) => m !== me);
    const known = others.length > 1 && chat.addedBy ? [chat.addedBy] : others;
    const ops: Op[] = [{ chat: { ...chat, request: false } }];
    for (const identity of known) {
      if (identity !== me && !this.known.has(identity)) ops.push({ person: { identity, verified: false } });
    }
    await this.run(() => ({ step: NOTHING, ops }));
  }

  /** Deletes a conversation from this device, silently: nobody is told,
   * and its history, files and keys are gone. */
  async deleteChat(conversation: string): Promise<void> {
    await this.run((d, now) => ({ step: d.forget(now, conversation), ops: [{ forget: conversation }] }));
  }

  /** Blocks someone: nothing from them reaches this device again. A
   * conversation with only them in it is deleted. */
  async block(identity: string, conversation?: string, alone = false): Promise<void> {
    await this.run((d) => ({ step: d.block(identity) }));
    if (conversation && alone) await this.deleteChat(conversation);
  }

  blocked(): string[] {
    return this.device.blocked();
  }

  async unblock(identity: string): Promise<void> {
    await this.run((d) => ({ step: d.unblock(identity) }));
  }

  /** Reports someone to krypt with the last messages they sent here (the
   * only thing that leaves the device), then blocks them. */
  async reportAbuse(conversation: string, identity: string, reason: string, alone: boolean): Promise<boolean> {
    const rows = await store.messages(this.db, conversation);
    const messages = rows
      .filter((r) => r.from === identity && !r.system)
      .slice(-REPORT_MESSAGES_MAX)
      .map((r) => ({
        at: new Date(r.at).toISOString(),
        text: r.file ? `[${r.file.mediaType} file, ${r.file.size} bytes]` : r.text.slice(0, REPORT_TEXT_MAX),
      }));
    const body = JSON.stringify({ version: 1, reported: identity, reason, messages });
    let sent = false;
    try {
      const response = await fetch(`${this.mailboxBase}/v1/report`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      sent = response.ok;
    } catch {
      // Blocking still happens.
    }
    await this.block(identity, conversation, alone);
    return sent;
  }

  /** Sets the conversation's disappearing-message timer for everyone. */
  async setTimer(conversation: string, seconds: number): Promise<void> {
    await this.run((d, now) => ({ step: d.setTimer(now, conversation, seconds) }));
  }

  timerOf(conversation: string): number {
    return this.device.timer(conversation);
  }

  /** Messages now on screen: disappearing ones start their clock. */
  async shown(rows: MessageRow[]): Promise<void> {
    const now = Date.now();
    const ops: Op[] = rows
      .filter((r) => r.expires && r.deleteAt === undefined)
      .map((r) => ({ shown: r.id, deleteAt: now + r.expires! * 1000 }));
    if (ops.length > 0) await this.run(() => ({ step: NOTHING, ops }));
  }

  private sweepAt(at: number) {
    if (this.sweeping && this.sweeping.at <= at) return;
    if (this.sweeping) clearTimeout(this.sweeping.timer);
    const delay = Math.min(Math.max(at - Date.now(), 0) + 50, TIMEOUT_MAX_MS);
    this.sweeping = { at, timer: setTimeout(() => void this.sweep(), delay) };
  }

  /** Deletes disappearing messages that are due, with their files. */
  private async sweep(): Promise<void> {
    if (this.sweeping) clearTimeout(this.sweeping.timer);
    this.sweeping = undefined;
    if (this.stopped) return;
    const { due, next } = await store.expiring(this.db, Date.now());
    if (due.length > 0) {
      const ops: Op[] = due.flatMap((row): Op[] => (row.file ? [{ del: row.id }, { dropFile: row.file.id }] : [{ del: row.id }]));
      await this.run(() => ({ step: NOTHING, ops }));
    }
    if (next !== undefined) this.sweepAt(next);
  }

  async sendCall(conversation: string, signal: CallSignal): Promise<void> {
    await this.run((d, now) => ({ step: d.sendCall(now, conversation, signal).step }));
  }

  /** ICE servers for a call in this conversation: Cloudflare's STUN and
   * TURN, with relay credentials only members get. Reused for a while;
   * `fresh` asks for new ones (a long call renewing them). */
  iceServers(conversation: string, fresh = false): Promise<RTCIceServer[]> {
    const cached = this.ice.get(conversation);
    if (cached && !fresh && cached.until > Date.now()) return cached.servers;
    const servers = this.fetchIce(conversation);
    this.ice.set(conversation, { servers, until: Date.now() + ICE_REUSE_MS });
    servers.then(
      (s) => s === STUN_ONLY && this.ice.delete(conversation),
      () => this.ice.delete(conversation),
    );
    return servers;
  }

  private async fetchIce(conversation: string): Promise<RTCIceServer[]> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const auth = await this.run((d) => ({ step: NOTHING, value: d.turnAuth(conversation) }));
      let response: Response;
      try {
        response = await fetch(`${this.mailboxBase}/v1/turn/${conversation}`, {
          method: "POST",
          headers: { "krypt-auth": auth! },
        });
      } catch {
        break;
      }
      if (response.ok) {
        const { iceServers } = (await response.json()) as { iceServers: RTCIceServer[] };
        this.iceTtlS = Number(response.headers.get("krypt-ttl") ?? 0);
        // Browsers block port 53; waiting on it would only delay the call.
        return iceServers
          .map((server) => ({
            ...server,
            urls: (Array.isArray(server.urls) ? server.urls : [server.urls]).filter((url) => !/:53(\?|$)/.test(url)),
          }))
          .filter((server) => server.urls.length > 0);
      }
      // A commit just made the proof stale: catch up and ask again.
      if (response.status !== 409) break;
      await this.run((d, now) => ({ step: d.pollNow(now) }));
      await sleep(400);
    }
    // Without relay credentials, direct paths still work.
    return STUN_ONLY;
  }

  /** A call's history row. */
  async recordCall(conversation: string, call: CallRecord): Promise<void> {
    await this.run(() => ({ step: NOTHING, ops: [system(conversation, "call", [], { call })] }));
  }

  /** Shares a file: cleans and previews it, keeps it here, then uploads it
   * (resuming after a reload) and sends the message once every part is
   * stored. Resolves once it is queued. */
  /** Sends a recorded voice message: scrubbed, uploaded, then shared. */
  async sendVoice(conversation: string, recorded: Blob, durationMs: number, waveform: number[]): Promise<void> {
    const { blob, mediaType } = await prepareVoice(recorded);
    if (blob.size > VOICE_SIZE_MAX) throw new FileTooLarge();
    const { id, key } = this.device.newFile();
    const file: FileRow = {
      id,
      key,
      size: blob.size,
      name: mediaType === "audio/webm" ? "voice.webm" : "voice.m4a",
      mediaType,
      width: 0,
      height: 0,
      thumbnail: new Uint8Array(),
      state: "uploading",
    };
    const voice = { durationMs: Math.min(Math.round(durationMs), VOICE_DURATION_MAX_MS), waveform };
    const row: MessageRow = {
      id: `${conversation}:up:${id}`,
      conversation,
      order: nextOrder(),
      at: Date.now(),
      mine: true,
      text: "",
      file,
      voice,
      state: "queued",
    };
    const upload: UploadRow = { id, conversation, row: row.id, file, done: 0, voice };
    await this.queued(() => store.beginUpload(this.db, upload, blob, row));
    this.announce({ ops: [{ put: row }], events: [] });
    void this.upload(upload);
  }

  async sendFile(conversation: string, picked: File): Promise<void> {
    const limits = fileLimits();
    if (picked.size > limits.sizeMax) throw new FileTooLarge();
    const prepared = await prepare(picked);
    if (prepared.blob.size > limits.sizeMax) throw new FileTooLarge();
    const { id, key } = this.device.newFile();
    const file: FileRow = {
      id,
      key,
      size: prepared.blob.size,
      name: prepared.name,
      mediaType: prepared.mediaType,
      width: prepared.width,
      height: prepared.height,
      thumbnail: prepared.thumbnail,
      state: "uploading",
    };
    const row: MessageRow = {
      id: `${conversation}:up:${id}`,
      conversation,
      order: nextOrder(),
      at: Date.now(),
      mine: true,
      text: "",
      file,
      state: "queued",
    };
    const upload: UploadRow = { id, conversation, row: row.id, file, done: 0 };
    const blob = new Blob([prepared.blob], { type: storedType(file.mediaType) });
    await this.queued(() => store.beginUpload(this.db, upload, blob, row));
    this.announce({ ops: [{ put: row }], events: [] });
    void this.upload(upload);
  }

  /** Runs `work` in turn with the device's steps. */
  private queued<T>(work: () => Promise<T>): Promise<T> {
    const next = this.queue.then(work);
    this.queue = next.catch(() => {});
    return next;
  }

  /** Uploads what is left of a file, then shares it. */
  async upload(upload: UploadRow): Promise<void> {
    if (this.moving.has(upload.id) || this.stopped) return;
    this.moving.add(upload.id);
    try {
      const blob = await store.file(this.db, upload.id);
      if (!blob) return;
      const { partSize } = fileLimits();
      const { size, key } = upload.file;
      const parts = fileParts(size);
      for (let part = upload.done; part < parts; part++) {
        const plain = new Uint8Array(await blob.slice(part * partSize, (part + 1) * partSize).arrayBuffer());
        const sealed = sealPart(key, size, part, plain) as Uint8Array<ArrayBuffer>;
        await this.storePart(upload, part, sealed, (sent) => this.report(upload.id, (part * partSize + sent) / Math.max(size, 1)));
        upload = { ...upload, done: part + 1 };
        await store.putUpload(this.db, upload);
      }
      const placeholder = await store.message(this.db, upload.row);
      // Disappeared (or deleted) while uploading: never shared.
      if (!placeholder) return;
      await this.run((d, now) => {
        const expires = d.timer(upload.conversation);
        const { senderSeq, step } = upload.voice
          ? d.sendContent(now, upload.conversation, {
              type: "voice",
              file: shareable(upload.file),
              durationMs: upload.voice.durationMs,
              waveform: new Uint8Array(upload.voice.waveform),
            })
          : d.sendFile(now, upload.conversation, shareable(upload.file));
        const row: MessageRow = {
          id: `${upload.conversation}:me:${senderSeq}`,
          conversation: upload.conversation,
          order: placeholder?.order ?? nextOrder(),
          at: placeholder?.at ?? now,
          mine: true,
          text: "",
          file: { ...upload.file, state: "ready" },
          ...(upload.voice && { voice: upload.voice }),
          state: "queued",
          ...(expires > 0 && { expires, deleteAt: now + expires * 1000 }),
        };
        return { step, ops: [{ del: upload.row }, { put: row }, { uploaded: upload.id }] };
      });
    } catch (error) {
      if (this.stopped) return;
      console.warn("upload failed", error);
      const failed = await store.message(this.db, upload.row);
      if (failed?.file) await this.save({ ...failed, file: { ...failed.file, state: "failed" } });
    } finally {
      this.moving.delete(upload.id);
      this.report(upload.id, undefined);
    }
  }

  /** Retries an upload that failed. */
  async retryUpload(row: MessageRow): Promise<void> {
    const upload = (await store.uploads(this.db)).find((u) => u.row === row.id);
    if (!upload || !row.file) return;
    await this.save({ ...row, file: { ...row.file, state: "uploading" } });
    void this.upload(upload);
  }

  /** Stores one part, retrying until the edge has it. A stale proof (the
   * group moved to a new epoch) is renewed after catching up. */
  private async storePart(upload: UploadRow, part: number, sealed: Uint8Array<ArrayBuffer>, onProgress: (sent: number) => void) {
    let delay = RETRY_MIN_MS;
    for (;;) {
      if (this.stopped) throw new Error("the device has stopped");
      const auth = this.device.fileAuth(upload.conversation, upload.id, part, sealed.length);
      const url = partUrl(this.mailboxBase, upload.conversation, upload.id, part);
      const status = await putPart(url, sealed, auth, onProgress);
      if (status === 200 || status === 201) return;
      if (status === 409) {
        void this.run((d, now) => ({ step: d.pollNow(now) }));
        await sleep(RETRY_MIN_MS);
        continue;
      }
      if (status === 400 || status === 403 || status === 404 || status === 413) throw new UploadRefused(`status ${status}`);
      // Over a limit, the edge unavailable, or no network: back off.
      await sleep(delay * (1 + Math.random() / 4));
      delay = Math.min(delay * 2, RETRY_MAX_MS);
    }
  }

  /** Fetches and opens a shared file, keeping it on this device. */
  async download(row: MessageRow): Promise<void> {
    const file = row.file;
    if (!file || this.moving.has(file.id) || this.stopped) return;
    this.moving.add(file.id);
    try {
      const { partSize } = fileLimits();
      const parts = fileParts(file.size);
      const plain: Uint8Array<ArrayBuffer>[] = [];
      let state: FileRow["state"] = "ready";
      for (let part = 0; part < parts && state === "ready"; part++) {
        const expected = Math.min(partSize, file.size - part * partSize) + 16;
        let delay = RETRY_MIN_MS;
        for (let attempt = 0; ; attempt++) {
          const url = partUrl(this.mailboxBase, row.conversation, file.id, part);
          const got = await getPart(url, expected, (n) => this.report(file.id, (part * partSize + n) / Math.max(file.size, 1)));
          if (got instanceof Uint8Array) {
            try {
              plain.push(openPart(file.key, file.size, part, got) as Uint8Array<ArrayBuffer>);
            } catch {
              state = "damaged";
            }
            break;
          }
          if (got === 404) {
            state = "expired";
            break;
          }
          if (attempt >= 5 || this.stopped) {
            state = "failed";
            break;
          }
          await sleep(delay);
          delay = Math.min(delay * 2, RETRY_MAX_MS);
        }
      }
      const blob = state === "ready" ? new Blob(plain, { type: storedType(file.mediaType) }) : undefined;
      await this.run(() => ({ step: NOTHING, ops: [{ downloaded: { row: row.id, file: file.id, state, ...(blob && { blob }) } }] }));
    } finally {
      this.moving.delete(file.id);
      this.report(file.id, undefined);
    }
  }

  /** A shared file's contents, if they are on this device. */
  file(id: string): Promise<Blob | undefined> {
    return store.file(this.db, id);
  }

  /** Rewrites a history row (no device step). */
  private async save(row: MessageRow): Promise<void> {
    await this.run(() => ({ step: NOTHING, ops: [{ put: row }] }));
  }

  async savePerson(person: PersonRow): Promise<void> {
    await this.run(() => ({ step: NOTHING, ops: [{ person }] }));
  }

  stop() {
    this.halt();
    this.release();
  }

  /** Stops everything but keeps the tab's lock. */
  private halt() {
    this.stopped = true;
    clearInterval(this.timer);
    this.mailbox.close();
  }

  // ---- This identity's other devices --------------------------------------

  /** What a linked or restored device gets of this device's own data. */
  async appSnapshot(): Promise<Uint8Array<ArrayBuffer>> {
    const [people, chats] = await Promise.all([store.people(this.db), store.chats(this.db)]);
    return new TextEncoder().encode(JSON.stringify({ people, chats }));
  }

  /** Takes in what `appSnapshot` gave, on a new device. */
  async importApp(bytes: Uint8Array, contacts: string[] = []): Promise<void> {
    let data: { people?: PersonRow[]; chats?: ChatRow[] } = {};
    try {
      data = JSON.parse(new TextDecoder().decode(bytes)) as typeof data;
    } catch {
      // Nothing to take in.
    }
    const ops: Op[] = [];
    const people = new Map((data.people ?? []).map((p) => [p.identity, p]));
    for (const card of contacts) {
      const identity = cardIdentity(card);
      if (identity) people.set(identity, { verified: false, ...people.get(identity), identity, card });
    }
    for (const person of people.values()) ops.push({ person });
    for (const chat of data.chats ?? []) ops.push({ chat });
    if (ops.length > 0) await this.run(() => ({ step: NOTHING, ops }));
  }

  /** Links the new device showing `code`: seals this identity for it,
   * waits for its answer, then adds it to every conversation. */
  async linkNewDevice(code: string, signal: AbortSignal): Promise<void> {
    const key = await takeNow(this.mailboxBase, linkKeyDrop(code));
    if (!key) throw new LinkCodeUsed();
    const payload = this.device.linkPayload(await this.appSnapshot());
    // Throws if the key is not the one the code names.
    const offer = LinkOffer.seal(code, key, payload);
    await put(this.mailboxBase, offer.drop, offer.sealed as Uint8Array<ArrayBuffer>);
    const reply = await take(this.mailboxBase, offer.replyDrop, signal);
    const card = offer.openReply(reply);
    await this.run((d, now) => ({ step: d.addDevice(now, card) }));
  }

  /** This identity's other devices, as cards. */
  devices(): string[] {
    return this.device.devices();
  }

  async removeDevice(card: string): Promise<void> {
    await this.run((d, now) => ({ step: d.removeDevice(now, card) }));
  }

  /** A backup of this identity, its contacts and this device's data, sealed
   * under a passkey's PRF output. */
  async sealBackup(prf: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    return this.device.sealBackup(await this.appSnapshot(), prf) as Uint8Array<ArrayBuffer>;
  }

  /** This identity's signature claiming `handle` for this device's card. */
  signHandle(handle: string, challenge: Uint8Array): Uint8Array<ArrayBuffer> {
    return this.device.signHandle(handle, challenge) as Uint8Array<ArrayBuffer>;
  }

  /** Burns this device: everything krypt stored in this browser is gone. */
  /** Deletes this device: its push registration and service worker (so
   * no later identity on this browser shares the push endpoint), then all
   * it stored. The tab's lock is held until it is gone, so no other tab
   * opens the burned device meanwhile. */
  async burn(): Promise<void> {
    this.halt();
    await this.queue;
    try {
      const registration = await navigator.serviceWorker?.getRegistration();
      await (await registration?.pushManager.getSubscription())?.unsubscribe();
      await registration?.unregister();
    } catch {
      // Without push or a worker there is nothing to remove.
    }
    await store.destroy(this.db);
    this.release();
  }
}

/** What the message carries: everything but this device's display state. */
function shareable(file: FileRow): SharedFile {
  const { state: _, ...shared } = file;
  return shared;
}

export { cardIdentity, fingerprintOf, isContactCard, safetyNumber } from "../core/krypt_wasm.js";
import { cardIdentity } from "../core/krypt_wasm.js";
