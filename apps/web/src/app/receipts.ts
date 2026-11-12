// Read receipts: when someone's messages are on screen, this device tells
// them (decision 49). Only in one-to-one chats and groups of at most eight,
// never in message requests, batched every two seconds, and quietly (a
// receipt wakes nobody). On by default; turning them off also stops showing
// who read your messages, as in other messengers.

import { createSignal } from "solid-js";
import type { ConversationInfo } from "../core/krypt_wasm.js";
import { refOf, type Runtime } from "../runtime/device";
import type { ChatRow, MessageRow } from "../runtime/store";

/** Receipts go out at most this often per conversation. */
const BATCH_MS = 2_000;
/** Larger groups get no receipts: one per reader per read would crowd
 * their log. */
export const RECEIPT_MEMBERS_MAX = 8;
const KEY = "krypt.receipts";

function setting(): boolean {
  try {
    return localStorage.getItem(KEY) !== "0";
  } catch {
    return true;
  }
}

export function createReceipts(
  rt: Runtime,
  conversation: (id: string) => ConversationInfo | undefined,
  isRequest: (id: string) => boolean,
  chat: (id: string) => ChatRow | undefined,
) {
  const [on, setOn] = createSignal(setting());
  /** Per conversation: the newest seq already reported, by sender device. */
  const reported = new Map<string, Map<string, number>>();
  const waiting = new Map<string, { rows: MessageRow[]; timer: ReturnType<typeof setTimeout> }>();

  const eligible = (id: string) => {
    const c = conversation(id);
    return !!c && c.active && !isRequest(id) && c.members.length <= RECEIPT_MEMBERS_MAX;
  };

  /** Incoming rows newer than what was last reported, by their sender device. */
  const unreported = (id: string, rows: MessageRow[]) => {
    const done = reported.get(id) ?? new Map<string, number>();
    return rows.filter((row) => {
      if (row.mine || row.system || !row.from || row.from === rt.identity) return false;
      const ref = refOf(row, rt.deviceId);
      return !!ref && ref.seq > (done.get(ref.device) ?? 0);
    });
  };

  const flush = (id: string) => {
    const batch = waiting.get(id);
    waiting.delete(id);
    if (!batch || !on() || !eligible(id)) return;
    const done = reported.get(id) ?? new Map<string, number>();
    for (const row of batch.rows) {
      const ref = refOf(row, rt.deviceId);
      if (ref && ref.seq > (done.get(ref.device) ?? 0)) done.set(ref.device, ref.seq);
    }
    reported.set(id, done);
    void rt.markRead(id, batch.rows);
  };

  return {
    on,
    setOn(next: boolean) {
      setOn(next);
      try {
        localStorage.setItem(KEY, next ? "1" : "0");
      } catch {
        // Back to the default next time.
      }
    },
    /** `rows` of a conversation are on screen. */
    seen(id: string, rows: MessageRow[]) {
      if (!on() || !eligible(id)) return;
      const fresh = unreported(id, rows);
      if (fresh.length === 0) return;
      const batch = waiting.get(id);
      if (batch) {
        batch.rows.push(...fresh);
        return;
      }
      waiting.set(id, { rows: fresh, timer: setTimeout(() => flush(id), BATCH_MS) });
    },
    /** Who (identities) has read one of this device's own messages. */
    readBy(row: MessageRow): string[] {
      if (!on() || !row.mine) return [];
      const ref = /:me:(\d+)$/.exec(row.id);
      const marks = chat(row.conversation)?.read;
      if (!ref || !marks) return [];
      const seq = Number(ref[1]);
      return Object.entries(marks)
        .filter(([, through]) => (through.me ?? 0) >= seq)
        .map(([reader]) => reader);
    },
  };
}

export type Receipts = ReturnType<typeof createReceipts>;
