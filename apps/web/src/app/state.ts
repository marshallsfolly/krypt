// What the views show: conversations, their messages and the people in
// them. Loaded from IndexedDB once, then kept current from each committed
// step, so the screen only ever shows what is already durable.

import { batch, createSignal } from "solid-js";
import { createStore, produce } from "solid-js/store";
import { linkCodeOf, type ConversationInfo, type Policy } from "../core/krypt_wasm.js";
import { Calls, type CallView } from "../runtime/call";
import { createPresence, type Presence } from "./presence";
import { createReceipts } from "./receipts";
import { cardIdentity, fingerprintOf, type Runtime } from "../runtime/device";
import * as db from "../runtime/store";
import type { ChatRow, MessageRow, PersonRow } from "../runtime/store";
import { strings } from "./strings";

export type { MessageRow, PersonRow, ConversationInfo };

const structural = new Set(["started", "joined", "membersAdded", "membersRemoved", "removed", "desync", "timer", "rules"]);

const RELAY_CALLS = "krypt.relayCalls";

function relayCalls(): boolean {
  try {
    return localStorage.getItem(RELAY_CALLS) === "1";
  } catch {
    return false;
  }
}

/** Says who is calling when krypt is in the background. The name never
 * leaves this device: the notification is shown locally. */
async function notifyCall(view: CallView, name: string) {
  if (!document.hidden || !("Notification" in window) || Notification.permission !== "granted") return;
  const registration = await navigator.serviceWorker?.getRegistration();
  await registration?.showNotification(strings.calls.notify(name), {
    body: view.video ? strings.calls.incomingVideo : strings.calls.incomingVoice,
    tag: `call:${view.id}`,
    requireInteraction: true,
  });
}

export async function createAppState(rt: Runtime) {
  const [conversations, setConversations] = createSignal<ConversationInfo[]>(rt.conversations());
  const [people, setPeople] = createStore<Record<string, PersonRow>>({});
  const [chats, setChats] = createStore<Record<string, ChatRow>>({});
  const [blocked, setBlocked] = createSignal<string[]>(rt.blocked());
  const [devices, setDevices] = createSignal<string[]>(rt.devices());
  // The timer and name of each conversation, refreshed when one changes.
  const [timers, setTimers] = createStore<Record<string, number>>({});
  /** Requests to join groups this device is an admin of (read again from
   * each group's requests log when krypt starts), minus those declined. */
  const [joinRequests, setJoinRequests] = createStore<Record<string, { id: string; identity: string; name: string }[]>>({});
  const DECLINED = "krypt.declined";
  const declined = new Set<string>(
    (() => {
      try {
        return JSON.parse(localStorage.getItem(DECLINED) ?? "[]") as string[];
      } catch {
        return [];
      }
    })(),
  );
  const [pendingJoins, setPendingJoins] = createSignal(rt.pendingJoins());
  /** A group, by what it shows now: more than one other member, a name, or
   * an invite link. Remembered (`ChatRow.group`), since a group that
   * shrinks to two people is still a group. */
  const looksLikeGroup = (c: ConversationInfo) =>
    c.members.filter((m) => m !== rt.identity).length > 1 || !!rt.groupName(c.id) || !!rt.policy(c.id)?.link;
  const noteGroups = () => {
    for (const c of rt.conversations()) if (!chats[c.id]?.group && looksLikeGroup(c)) void rt.markGroup(c.id);
  };
  const linkCodes = new Map<string, string>();
  /** Until when each conversation is muted (Infinity: until unmuted). */
  const [mutes, setMutes] = createStore<Record<string, number | undefined>>({});
  // Mutes run out; a minute is fine enough for showing it.
  const [minute, setMinute] = createSignal(Date.now());
  setInterval(() => setMinute(Date.now()), 60_000);
  const [names, setNames] = createStore<Record<string, string>>({});
  const [last, setLast] = createStore<Record<string, MessageRow>>({});
  const [threads, setThreads] = createStore<Record<string, MessageRow[]>>({});
  const [arrivals, setArrivals] = createSignal<MessageRow | undefined>();
  // Files moving right now: how far along, 0 to 1.
  const [progress, setProgress] = createStore<Record<string, number | undefined>>({});
  rt.onProgress((id, fraction) => setProgress(id, fraction));
  // Rows that arrived while the app was open animate in; history does not.
  const fresh = new Set<string>();

  /** A conversation's newest row, replaced whole (setting a store path to
   * an object would merge it into the old row, keeping fields it lacks). */
  const putLast = (row: MessageRow) =>
    setLast(
      produce((all) => {
        all[row.conversation] = row;
      }),
    );

  for (const person of await db.people(rt.db)) setPeople(person.identity, person);
  for (const chat of await db.chats(rt.db)) setChats(chat.id, chat);
  noteGroups();
  for (const c of conversations()) {
    setTimers(c.id, rt.timerOf(c.id));
    setNames(c.id, rt.groupName(c.id));
    setMutes(c.id, rt.mutedUntil(c.id));
  }
  for (const c of conversations()) {
    const [row] = await db.messages(rt.db, c.id, 1);
    if (row) putLast(row);
  }

  const upsert = (row: MessageRow) => {
    if (!threads[row.conversation]) return;
    setThreads(
      row.conversation,
      produce((rows) => {
        const at = rows.findIndex((r) => r.id === row.id);
        if (at >= 0) rows[at] = row;
        else rows.push(row);
      }),
    );
  };

  // Created once the state it reads is (below); commits can arrive before.
  let presence: Presence | undefined;

  rt.onCommit(({ ops, events, changed }) => {
    batch(() => {
      for (const op of ops) {
        if ("put" in op) {
          if (!op.put.mine && !op.put.system && op.put.from) presence?.spoke(op.put.conversation, op.put.from);
          if (!fresh.has(op.put.id)) {
            fresh.add(op.put.id);
            setTimeout(() => fresh.delete(op.put.id), 2_000);
          }
          upsert(op.put);
          putLast(op.put);
          if (!op.put.mine && !op.put.system) setArrivals(op.put);
        } else if ("person" in op) {
          setPeople(op.person.identity, op.person);
        } else if ("chat" in op) {
          setChats(op.chat.id, op.chat);
        } else if ("forget" in op) {
          setChats(produce((all) => void delete all[op.forget]));
          setThreads(produce((all) => void delete all[op.forget]));
          setLast(produce((all) => void delete all[op.forget]));
        } else if ("shown" in op) {
          const [conversation] = op.shown.split(":");
          const at = threads[conversation!]?.findIndex((r) => r.id === op.shown) ?? -1;
          if (at >= 0) setThreads(conversation!, at, "deleteAt", op.deleteAt);
        } else if ("del" in op) {
          const [conversation] = op.del.split(":");
          const rows = threads[conversation!];
          const at = rows?.findIndex((r) => r.id === op.del) ?? -1;
          if (at >= 0) setThreads(conversation!, produce((rows) => void rows.splice(at, 1)));
          if (last[conversation!]?.id === op.del) {
            // The preview shows what is left.
            void db.messages(rt.db, conversation!, 1).then(([row]) =>
              setLast(produce((all) => (row ? (all[conversation!] = row) : delete all[conversation!]))),
            );
          }
        } else if ("uploaded" in op || "dropFile" in op || "change" in op || "read" in op || "downloaded" in op) {
          // Bookkeeping, or shown below through what the commit changed.
        } else {
          const [conversation] = op.sent.split(":");
          const rows = threads[conversation!];
          const at = rows?.findIndex((r) => r.id === op.sent) ?? -1;
          if (at >= 0) setThreads(conversation!, at, "state", "sent");
          if (last[conversation!]?.id === op.sent) setLast(conversation!, "state", "sent");
        }
      }
      // Reactions, edits and deletions: the rows as they are now. Quietly:
      // no arrival, no entrance.
      for (const row of changed?.rows ?? []) {
        upsert(row);
        if (last[row.conversation]?.id === row.id) putLast(row);
      }
      for (const chat of changed?.chats ?? []) setChats(chat.id, chat);
      if (events.some((e) => structural.has(e.type)) || ops.some((op) => "forget" in op)) {
        setConversations(rt.conversations());
        noteGroups();
      }
      for (const e of events) {
        if (e.type === "joinRequest" && !declined.has(e.id)) {
          setJoinRequests(e.conversation, (list = []) =>
            list.some((r) => r.id === e.id) ? list : [...list, { id: e.id, identity: e.identity, name: e.name }],
          );
        }
        if (e.type === "membersAdded") {
          setJoinRequests(e.conversation, (list = []) => list.filter((r) => !e.identities.includes(r.identity)));
        }
        if (e.type === "joined") setPendingJoins(rt.pendingJoins());
        if (e.type === "timer" || e.type === "joined" || e.type === "timerRefused") setTimers(e.conversation, rt.timerOf(e.conversation));
        if (e.type === "renamed" || e.type === "joined" || e.type === "started") setNames(e.conversation, rt.groupName(e.conversation));
      }
    });
  });

  const name = (identity: string): string => {
    if (identity === rt.identity) return "You";
    return people[identity]?.name || fingerprintOf(identity).slice(0, 9);
  };

  const [relay, setRelay] = createSignal(relayCalls());
  const calls = new Calls(rt, relay, (view) => void notifyCall(view, name(view.peer)));

  const isRequest = (id: string) => chats[id]?.request ?? false;
  presence = createPresence(rt, () =>
    conversations()
      .filter((c) => c.active && !isRequest(c.id))
      .sort((a, b) => (last[b.id]?.order ?? 0) - (last[a.id]?.order ?? 0)),
  );

  const receipts = createReceipts(
    rt,
    (id) => conversations().find((c) => c.id === id),
    isRequest,
    (id) => chats[id],
  );

  return {
    rt,
    presence,
    receipts,
    /** Whether a conversation is muted now. */
    isMuted: (id: string) => (mutes[id] ?? 0) > minute(),
    mutedUntil: (id: string) => ((mutes[id] ?? 0) > minute() ? mutes[id] : undefined),
    async mute(id: string, until: number | undefined) {
      await rt.mute(id, until);
      setMutes(id, rt.mutedUntil(id));
    },
    isArchived: (id: string) => chats[id]?.archived ?? false,
    async archive(id: string, archived: boolean) {
      await rt.archive(id, archived);
    },
    search: (query: string) => rt.search(query),
    /** A group's rules (undefined: from before admins; everyone may do
     * everything) and admins, read again when the group changes. */
    policy: (id: string) => (conversations(), rt.policy(id)),
    admins: (id: string) => (conversations(), rt.admins(id)),
    amAdmin: (id: string) => (conversations(), rt.admins(id).includes(rt.identity)),
    /** Whether this device may add people / rename the group. */
    may(id: string, what: "add" | "edit"): boolean {
      conversations();
      const policy = rt.policy(id);
      return !policy || policy[what] === "everyone" || rt.admins(id).includes(rt.identity);
    },
    /** Changes a group's rules, starting from what they are (or, for a
     * group from before admins, from everyone being one). */
    async changeRules(id: string, change: (policy: Policy) => Policy) {
      const c = conversations().find((c) => c.id === id);
      const current = rt.policy(id) ?? { admins: c?.members ?? [], add: "everyone", edit: "everyone" };
      await rt.setPolicy(id, change({ ...current, admins: [...current.admins] }));
    },
    /** Removes someone; a link they knew is reset, since its secret would
     * still let them read who asks to join. */
    async removeMember(id: string, identity: string) {
      await rt.removeMember(id, identity);
      if (rt.policy(id)?.link) await this.setLink(id, true);
    },
    /** A group's invite link code (what follows `#join=`), if it has one. */
    linkCode(id: string): string | undefined {
      conversations();
      const seed = rt.policy(id)?.link;
      if (!seed) return undefined;
      const key = `${id}:${seed}`;
      if (!linkCodes.has(key)) linkCodes.set(key, linkCodeOf(seed, id));
      return linkCodes.get(key);
    },
    /** Turns a group's invite link on (a new one, so this also resets it)
     * or off. */
    async setLink(id: string, on: boolean) {
      const seed = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");
      await this.changeRules(id, (p) => ({ ...p, link: on ? seed : undefined }));
    },
    joinRequests: (id: string) => joinRequests[id] ?? [],
    async approveJoin(id: string, request: string) {
      await rt.approveJoin(id, request);
      setJoinRequests(id, (list = []) => list.filter((r) => r.id !== request));
    },
    declineJoin(id: string, request: string) {
      declined.add(request);
      try {
        localStorage.setItem(DECLINED, JSON.stringify([...declined].slice(-512)));
      } catch {
        // Shown again next time; harmless.
      }
      setJoinRequests(id, (list = []) => list.filter((r) => r.id !== request));
    },
    joinHeader: (code: string) => rt.joinHeader(code),
    async askToJoin(code: string, header: Uint8Array, name: string) {
      const sent = await rt.askToJoin(code, header, name);
      setPendingJoins(rt.pendingJoins());
      return sent;
    },
    pendingJoins,
    calls,
    isRequest,
    /** Conversations waiting for this device to accept them. */
    requests: () => conversations().filter((c) => isRequest(c.id)),
    timer: (id: string) => timers[id] ?? 0,
    async setTimer(id: string, seconds: number) {
      await rt.setTimer(id, seconds);
      setTimers(id, rt.timerOf(id));
    },
    blocked,
    /** This identity's other devices (cards). */
    devices,
    refreshDevices: () => setDevices(rt.devices()),
    async accept(id: string) {
      const c = conversations().find((c) => c.id === id);
      await rt.accept(id, c?.members ?? []);
    },
    async deleteChat(id: string) {
      await rt.deleteChat(id);
    },
    /** Blocks someone; a conversation with only them in it goes too. */
    async block(identity: string, conversation?: string) {
      const c = conversation ? conversations().find((c) => c.id === conversation) : undefined;
      const alone = !!c && c.members.filter((m) => m !== rt.identity).length === 1;
      await rt.block(identity, conversation, alone);
      setBlocked(rt.blocked());
    },
    async unblock(identity: string) {
      await rt.unblock(identity);
      setBlocked(rt.blocked());
    },
    /** "Always relay calls", a per-device choice. */
    relayCalls: relay,
    setRelayCalls(on: boolean) {
      setRelay(on);
      try {
        localStorage.setItem(RELAY_CALLS, on ? "1" : "0");
      } catch {
        // Kept for this session only.
      }
    },
    me: rt.identity,
    /** Accepted conversations, newest activity first. */
    conversations: () =>
      conversations()
        .filter((c) => !isRequest(c.id))
        .sort((a, b) => (last[b.id]?.order ?? 0) - (last[a.id]?.order ?? 0)),
    conversation: (id: string) => conversations().find((c) => c.id === id),
    last: (id: string) => last[id],
    people,
    /** The newest message from someone else, for haptics and alerts. */
    arrivals,
    /** How far a file's upload or download is, 0 to 1, while it moves. */
    progress: (id: string) => progress[id],
    /** Whether a row just arrived (and should animate in). */
    fresh: (id: string) => fresh.has(id),
    name,
    /** The other members of a conversation. */
    others: (c: ConversationInfo) => c.members.filter((m) => m !== rt.identity),
    title(c: ConversationInfo): string {
      if (names[c.id]) return names[c.id]!;
      const others = c.members.filter((m) => m !== rt.identity);
      return others.length === 0 ? "New conversation" : others.map(name).join(", ");
    },
    /** A group's own name (empty: none). */
    groupName: (id: string) => names[id] ?? "",
    /** Whether a conversation is a group (more than one other person). */
    isGroup: (c: ConversationInfo) => !!chats[c.id]?.group || looksLikeGroup(c),
    async rename(id: string, value: string) {
      await rt.rename(id, value);
      setNames(id, rt.groupName(id));
    },
    async leaveGroup(id: string) {
      await rt.leaveGroup(id);
    },
    async startGroup(cards: string[], groupName: string) {
      const id = await rt.startGroup(cards, groupName);
      setNames(id, rt.groupName(id));
      return id;
    },
    /** People this device is connected with, who can be put in a group:
     * everyone in a conversation it has accepted (not a request), unblocked. */
    contacts(): { identity: string; card: string }[] {
      const cards = new Map<string, string>();
      for (const card of rt.knownContacts()) {
        const identity = cardIdentity(card);
        if (identity) cards.set(identity, card);
      }
      for (const person of Object.values(people)) {
        if (person.card && !cards.has(person.identity)) cards.set(person.identity, person.card);
      }
      const connected = new Set(
        conversations()
          .filter((c) => c.active && !isRequest(c.id))
          .flatMap((c) => c.members.filter((m) => m !== rt.identity)),
      );
      return [...connected]
        .filter((identity) => !blocked().includes(identity))
        .flatMap((identity) => {
          const card = cards.get(identity);
          return card ? [{ identity, card }] : [];
        });
    },
    thread(id: string): MessageRow[] | undefined {
      if (!threads[id]) {
        setThreads(id, []);
        void db.messages(rt.db, id).then((rows) => {
          // Rows committed while loading are already in the thread.
          const seen = new Set(threads[id]!.map((r) => r.id));
          setThreads(id, [...rows.filter((r) => !seen.has(r.id)), ...threads[id]!].sort((a, b) => a.order - b.order));
        });
      }
      return threads[id];
    },
    async savePerson(person: PersonRow) {
      await rt.savePerson(person);
    },
  };
}

export type AppState = Awaited<ReturnType<typeof createAppState>>;
