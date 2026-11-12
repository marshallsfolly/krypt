// IndexedDB: the device's own records ("core", written only by its steps)
// and the app's history ("messages", "people", "chats"). Both are written in
// one transaction per step, so the core never consumes a message the history
// does not also keep. Shared files are kept whole in "files" (by file id),
// and a file still uploading has its progress in "uploads". Disappearing
// messages are found by their deletion time ("byDeleteAt"). Reactions, edits
// and deletions that arrive before the message they are about wait in
// "parked" until it does.

const NAME = "krypt";
const VERSION = 4;
/** How long an edit or deletion may follow its message (sender clocks). */
export const CHANGE_WINDOW_MS = 24 * 60 * 60_000;
/** How long a change waits for a message that has not arrived. */
const PARKED_MS = 30 * 24 * 60 * 60_000;
/** Changes kept waiting for one message, and messages waited for in one
 * conversation: what a member can make this device store is bounded. */
const PARKED_CHANGES_MAX = 16;
const PARKED_PER_CHAT_MAX = 256;
/** A message that disappeared turns away changes for this long (its
 * sender's edit window, and a little more). */
const GONE_MS = 25 * 60 * 60_000;

export type SystemEvent =
  | "started"
  | "joined"
  | "membersAdded"
  | "membersRemoved"
  | "removed"
  | "inviteFailed"
  | "undecryptable"
  | "desync"
  | "call"
  | "timer"
  | "timerRefused"
  | "renamed"
  | "rules"
  | "refused"
  | "rulesBroken";

/** How a call went, as its history row shows it. */
export interface CallRecord {
  direction: "out" | "in";
  video: boolean;
  /** A group call. */
  group?: boolean;
  outcome: "completed" | "missed" | "declined" | "busy" | "unanswered" | "failed" | "elsewhere";
  /** Seconds connected, for a completed call. */
  seconds: number;
}

/** A shared file, as a message shows it. */
export interface FileRow {
  id: string;
  /** Hex; opens the stored parts. */
  key: string;
  size: number;
  name: string;
  mediaType: string;
  width: number;
  height: number;
  /** A small JPEG preview, or empty. */
  thumbnail: Uint8Array;
  /** "uploading" (own, not yet shared), "remote" (not downloaded),
   * "ready" (in the files store), "failed" (download failed; retry),
   * "damaged" (did not decrypt), "expired" (no longer stored). */
  state: "uploading" | "remote" | "ready" | "failed" | "damaged" | "expired";
}

/** A file this device is uploading: which parts are stored so far. */
export interface UploadRow {
  id: string;
  conversation: string;
  /** The placeholder message row shown while it uploads. */
  row: string;
  file: FileRow;
  done: number;
  /** A voice message: shared as one once uploaded. */
  voice?: { durationMs: number; waveform: number[] };
}

export interface MessageRow {
  /** `<conversation>:<device or "me">:<senderSeq>`, or `<conversation>:sys:<order>`. */
  id: string;
  conversation: string;
  /** Local arrival order: the display order. */
  order: number;
  /** The sender's clock, for display. */
  at: number;
  mine: boolean;
  /** Sender identity (hex); absent for this device's own messages. */
  from?: string;
  text: string;
  file?: FileRow;
  /** Own messages: queued until the mailbox has stored them. */
  state?: "queued" | "sent";
  /** Disappearing: seconds after it is first shown that it is deleted. */
  expires?: number;
  /** When it is deleted (ms), once it has been shown. */
  deleteAt?: number;
  /** A reply: the id of the message it answers. */
  replyTo?: string;
  /** Reactions, by identity (hex). */
  reactions?: Record<string, string>;
  /** Edited: the sender's clock at the last edit. */
  edited?: number;
  /** Deleted for everyone by its sender: no content is kept. */
  deleted?: boolean;
  /** A voice message (its audio is `file`). */
  voice?: { durationMs: number; waveform: number[] };
  system?: {
    event: SystemEvent;
    identities: string[];
    call?: CallRecord;
    /** A timer change: the new timer, in seconds (zero: off). */
    seconds?: number;
    /** A rename: the group's new name (empty: none). */
    name?: string;
    /** A change of rules: who became an admin, who stopped, and who may
     * now add people or rename the group. */
    rules?: { added: string[]; removed: string[]; add?: string; edit?: string; link?: string };
    /** Who removed `identities` (absent: they left). */
    by?: string;
  };
}

export interface PersonRow {
  identity: string;
  name?: string;
  verified: boolean;
  /** A card to reach them by (one of their devices), when known. */
  card?: string;
}

/** What this device decided about a conversation. A conversation someone
 * else started, with nobody this device knows, is a request until accepted. */
export interface ChatRow {
  id: string;
  request: boolean;
  /** Read receipts: for each reader (identity), the newest message read
   * from each sender device ("me" for this one). */
  read?: Record<string, Record<string, number>>;
  /** Archived on this device: out of the main list until it is unarchived
   * (or, unless muted, until a message arrives). */
  archived?: boolean;
  /** Ever a group (more than one other member, a name or an invite link):
   * it stays one when it shrinks to two people. */
  group?: boolean;
  /** Who added this device (whose request it is, if it is one). */
  addedBy?: string;
}

/** A change to a message, by someone who may or may not be allowed it. */
export type Change =
  | { react: { target: string; by: string; emoji: string } }
  | { edit: { target: string; by: string; me: string; text: string; at: number } }
  | { erase: { target: string; by: string; me: string; at: number } };

const targetOf = (change: Change) => ("react" in change ? change.react : "edit" in change ? change.edit : change.erase).target;

/** The row after `change`, or nothing if the change is not allowed: only a
 * message's sender may edit or delete it, within a day of sending it by
 * both messages' sender clocks (so every device decides alike), and nothing
 * changes a deleted message or a system row. */
export function applyChange(row: MessageRow, change: Change): MessageRow | undefined {
  if (row.system || row.deleted) return undefined;
  if ("react" in change) {
    const reactions = { ...row.reactions };
    if (change.react.emoji) reactions[change.react.by] = change.react.emoji;
    else delete reactions[change.react.by];
    return { ...row, reactions };
  }
  const { by, me, at } = "edit" in change ? change.edit : change.erase;
  const author = row.mine ? me : row.from;
  if (author !== by || at < row.at || at - row.at > CHANGE_WINDOW_MS) return undefined;
  if ("edit" in change) {
    if (row.file) return undefined;
    return { ...row, text: change.edit.text, edited: at };
  }
  const { file: _file, voice: _voice, replyTo: _reply, reactions: _reactions, ...kept } = row;
  return { ...kept, text: "", deleted: true };
}

export type Op =
  /** `once`: a message received, never written over one already here (a
   * device removed and added again could reuse its old numbers). */
  | { put: MessageRow; once?: true }
  | { sent: string }
  | { person: PersonRow }
  | { del: string }
  | { uploaded: string }
  | { chat: ChatRow }
  /** A file's contents, gone (its message disappeared). */
  | { dropFile: string }
  /** Everything kept about a conversation, gone. */
  | { forget: string }
  /** A disappearing message was first shown: it goes at `deleteAt`. */
  | { shown: string; deleteAt: number }
  /** A reaction, edit or deletion of a message (checked when applied). */
  | { change: Change }
  /** A member's read receipt: through these messages of each sender device. */
  | { read: { conversation: string; reader: string; through: [string, number][] } }
  /** A download finished: its contents (if it worked) and its state, kept
   * only if its message is still here and not deleted. */
  | { downloaded: { row: string; file: string; state: FileRow["state"]; blob?: Blob } };

/** What a commit changed besides its own rows, for the screen to show. */
export interface Changed {
  rows: MessageRow[];
  chats: ChatRow[];
}

// Keys and values are JS-owned copies (wasm-bindgen copies out of wasm memory).
type Write = [Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer> | null];

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("transaction aborted"));
  });
}

export async function open(): Promise<IDBDatabase> {
  const req = indexedDB.open(NAME, VERSION);
  req.onupgradeneeded = (event) => {
    const db = req.result;
    if (event.oldVersion < 1) {
      db.createObjectStore("core");
      const messages = db.createObjectStore("messages", { keyPath: "id" });
      messages.createIndex("byConversation", ["conversation", "order"]);
      db.createObjectStore("people", { keyPath: "identity" });
    }
    if (event.oldVersion < 2) {
      db.createObjectStore("files");
      db.createObjectStore("uploads", { keyPath: "id" });
    }
    if (event.oldVersion < 3) {
      db.createObjectStore("chats", { keyPath: "id" });
      req.transaction!.objectStore("messages").createIndex("byDeleteAt", "deleteAt");
    }
    if (event.oldVersion < 4) {
      // Changes waiting for their message, by its id: { changes, until }.
      db.createObjectStore("parked");
    }
  };
  const db = await request(req);
  // Another tab burning the device deletes the database: let it.
  db.onversionchange = () => db.close();
  return db;
}

/** Everything the device's steps have written, as `[key, value]` pairs. */
export async function loadCore(db: IDBDatabase): Promise<[Uint8Array, Uint8Array][]> {
  const tx = db.transaction("core", "readonly");
  const store = tx.objectStore("core");
  const [keys, values] = await Promise.all([request(store.getAllKeys()), request(store.getAll())]);
  return keys.map((key, i) => [new Uint8Array(key as ArrayBuffer), values[i] as Uint8Array]);
}

/** Persists a step's writes and the history it produced, atomically and
 * durably. Nothing the step decided may happen before this resolves. */
export async function commit(db: IDBDatabase, writes: Write[], ops: Op[]): Promise<Changed> {
  const tx = db.transaction(["core", "messages", "people", "uploads", "chats", "files", "parked"], "readwrite", {
    durability: "strict",
  });
  const core = tx.objectStore("core");
  for (const [key, value] of writes) {
    if (value === null) core.delete(key);
    else core.put(value, key);
  }
  const messages = tx.objectStore("messages");
  const parked = tx.objectStore("parked");
  const changed: Changed = { rows: [], chats: [] };
  const now = Date.now();
  /** Applies `changes` to the row `id` if it is here, else parks them
   * (within limits; never for a message that already disappeared). */
  const change = (id: string, changes: Change[]) => {
    const get = messages.get(id);
    get.onsuccess = () => {
      let row = get.result as MessageRow | undefined;
      if (!row) {
        const waiting = parked.get(id);
        waiting.onsuccess = () => {
          const found = waiting.result as Parked | undefined;
          if (found?.gone && found.until > now) return;
          const park = () =>
            parked.put({ changes: [...(found?.changes ?? []), ...changes].slice(-PARKED_CHANGES_MAX), until: now + PARKED_MS }, id);
          if (found) return park();
          const chat = id.slice(0, id.indexOf(":"));
          const count = parked.count(IDBKeyRange.bound(`${chat}:`, `${chat}:\uffff`));
          count.onsuccess = () => {
            if (count.result < PARKED_PER_CHAT_MAX) park();
          };
        };
        return;
      }
      let any = false;
      for (const c of changes) {
        const next = applyChange(row, c);
        if (!next) continue;
        if (next.deleted && row.file) {
          tx.objectStore("files").delete(row.file.id);
          tx.objectStore("uploads").delete(row.file.id);
        }
        row = next;
        any = true;
      }
      if (any) {
        messages.put(row);
        changed.rows.push(row);
      }
    };
  };
  for (const op of ops) {
    if ("put" in op) {
      const row = op.put;
      const write = () => {
        messages.put(row);
        // Changes that arrived before this message apply now.
        const waiting = parked.get(row.id);
        waiting.onsuccess = () => {
          const found = waiting.result as Parked | undefined;
          if (!found) return;
          parked.delete(row.id);
          if (found.until > now && !found.gone) change(row.id, found.changes);
        };
      };
      if (op.once) {
        const here = messages.get(row.id);
        here.onsuccess = () => {
          if (here.result === undefined) write();
        };
      } else write();
    } else if ("change" in op) change(targetOf(op.change), [op.change]);
    else if ("read" in op) {
      const { conversation, reader, through } = op.read;
      const get = tx.objectStore("chats").get(conversation);
      get.onsuccess = () => {
        const chat = (get.result as ChatRow | undefined) ?? { id: conversation, request: false };
        const marks = { ...chat.read?.[reader] };
        let moved = false;
        for (const [device, seq] of through) {
          if ((marks[device] ?? 0) < seq) {
            marks[device] = seq;
            moved = true;
          }
        }
        if (!moved) return;
        const next = { ...chat, read: { ...chat.read, [reader]: marks } };
        tx.objectStore("chats").put(next);
        changed.chats.push(next);
      };
    } else if ("chat" in op) {
      // Merged, so what else is kept about the chat (read receipts) stays.
      const chats = tx.objectStore("chats");
      const get = chats.get(op.chat.id);
      get.onsuccess = () => chats.put({ ...(get.result as ChatRow | undefined), ...op.chat });
    } else if ("person" in op) tx.objectStore("people").put(op.person);
    else if ("del" in op) {
      messages.delete(op.del);
      // Gone: changes still on their way are turned away, not kept.
      parked.put({ changes: [], until: now + GONE_MS, gone: true }, op.del);
    }
    else if ("uploaded" in op) tx.objectStore("uploads").delete(op.uploaded);
    else if ("downloaded" in op) {
      const { row: id, file, state, blob } = op.downloaded;
      const get = messages.get(id);
      get.onsuccess = () => {
        const row = get.result as MessageRow | undefined;
        // Deleted, gone or forgotten while it downloaded: nothing comes back.
        if (!row?.file || row.deleted || row.file.id !== file) return;
        if (blob) tx.objectStore("files").put(blob, file);
        const next = { ...row, file: { ...row.file, state } };
        messages.put(next);
        changed.rows.push(next);
      };
    }
    else if ("dropFile" in op) {
      tx.objectStore("files").delete(op.dropFile);
      tx.objectStore("uploads").delete(op.dropFile);
    } else if ("shown" in op) {
      const get = messages.get(op.shown);
      get.onsuccess = () => {
        const row = get.result as MessageRow | undefined;
        if (row && row.deleteAt === undefined) messages.put({ ...row, deleteAt: op.deleteAt });
      };
    } else if ("forget" in op) {
      tx.objectStore("chats").delete(op.forget);
      parked.delete(IDBKeyRange.bound(`${op.forget}:`, `${op.forget}:\uffff`));
      const range = IDBKeyRange.bound([op.forget, -Infinity], [op.forget, Infinity]);
      const cursor = messages.index("byConversation").openCursor(range);
      cursor.onsuccess = () => {
        const c = cursor.result;
        if (!c) return;
        const row = c.value as MessageRow;
        if (row.file) {
          tx.objectStore("files").delete(row.file.id);
          tx.objectStore("uploads").delete(row.file.id);
        }
        c.delete();
        c.continue();
      };
    } else {
      const get = messages.get(op.sent);
      get.onsuccess = () => {
        const row = get.result as MessageRow | undefined;
        if (row) messages.put({ ...row, state: "sent" });
      };
    }
  }
  await done(tx);
  return changed;
}

/** Text as search compares it: no accents, no case. */
export function fold(text: string): string {
  return text.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
}

/** Messages whose text contains `query` (ignoring case and accents),
 * newest first, at most `limit`. Everything is read here, on the device. */
export async function search(db: IDBDatabase, query: string, limit = 200): Promise<MessageRow[]> {
  const needle = fold(query.trim());
  if (!needle) return [];
  const found: MessageRow[] = [];
  return new Promise((resolve, reject) => {
    const cursor = db.transaction("messages", "readonly").objectStore("messages").openCursor();
    cursor.onerror = () => reject(cursor.error);
    cursor.onsuccess = () => {
      const c = cursor.result;
      if (!c) return resolve(found.sort((a, b) => b.order - a.order).slice(0, limit));
      const row = c.value as MessageRow;
      if (!row.system && !row.deleted && row.text && fold(row.text).includes(needle)) found.push(row);
      c.continue();
    };
  });
}

/** Changes waiting for their message, or a mark that it is gone. */
type Parked = { changes: Change[]; until: number; gone?: true };

/** Drops changes that waited too long for their message, and marks of
 * messages gone long enough. */
export async function dropParked(db: IDBDatabase, now: number): Promise<void> {
  const tx = db.transaction("parked", "readwrite");
  const cursor = tx.objectStore("parked").openCursor();
  cursor.onsuccess = () => {
    const c = cursor.result;
    if (!c) return;
    if ((c.value as Parked).until <= now) c.delete();
    c.continue();
  };
  return done(tx);
}

/** The newest `limit` messages of a conversation, oldest first. */
export async function messages(db: IDBDatabase, conversation: string, limit = 500): Promise<MessageRow[]> {
  const index = db.transaction("messages", "readonly").objectStore("messages").index("byConversation");
  const range = IDBKeyRange.bound([conversation, -Infinity], [conversation, Infinity]);
  const rows: MessageRow[] = [];
  return new Promise((resolve, reject) => {
    const cursor = index.openCursor(range, "prev");
    cursor.onerror = () => reject(cursor.error);
    cursor.onsuccess = () => {
      const c = cursor.result;
      if (!c || rows.length >= limit) return resolve(rows.reverse());
      rows.push(c.value as MessageRow);
      c.continue();
    };
  });
}

export async function message(db: IDBDatabase, id: string): Promise<MessageRow | undefined> {
  return request(db.transaction("messages", "readonly").objectStore("messages").get(id));
}

/** A shared file's contents, if this device has them. */
export async function file(db: IDBDatabase, id: string): Promise<Blob | undefined> {
  return request(db.transaction("files", "readonly").objectStore("files").get(id));
}

/** Starts an upload: the file and its placeholder row, together. */
export async function beginUpload(db: IDBDatabase, upload: UploadRow, blob: Blob, row: MessageRow): Promise<void> {
  const tx = db.transaction(["files", "uploads", "messages"], "readwrite", { durability: "strict" });
  tx.objectStore("files").put(blob, upload.id);
  tx.objectStore("uploads").put(upload);
  tx.objectStore("messages").put(row);
  return done(tx);
}

export async function putUpload(db: IDBDatabase, upload: UploadRow): Promise<void> {
  const tx = db.transaction("uploads", "readwrite", { durability: "strict" });
  tx.objectStore("uploads").put(upload);
  return done(tx);
}

export async function uploads(db: IDBDatabase): Promise<UploadRow[]> {
  return request(db.transaction("uploads", "readonly").objectStore("uploads").getAll());
}

export async function people(db: IDBDatabase): Promise<PersonRow[]> {
  return request(db.transaction("people", "readonly").objectStore("people").getAll());
}

export async function person(db: IDBDatabase, identity: string): Promise<PersonRow | undefined> {
  return request(db.transaction("people", "readonly").objectStore("people").get(identity));
}

export async function chats(db: IDBDatabase): Promise<ChatRow[]> {
  return request(db.transaction("chats", "readonly").objectStore("chats").getAll());
}

/** Messages due for deletion by `now`, and when the next one is due. */
export async function expiring(db: IDBDatabase, now: number): Promise<{ due: MessageRow[]; next?: number }> {
  const index = db.transaction("messages", "readonly").objectStore("messages").index("byDeleteAt");
  const [due, first] = await Promise.all([
    request(index.getAll(IDBKeyRange.upperBound(now))) as Promise<MessageRow[]>,
    request(index.get(IDBKeyRange.lowerBound(now, true))) as Promise<MessageRow | undefined>,
  ]);
  return { due, next: first?.deleteAt };
}

/** Destroys everything this browser holds for krypt. */
export async function destroy(db: IDBDatabase): Promise<void> {
  db.close();
  await request(indexedDB.deleteDatabase(NAME));
}
