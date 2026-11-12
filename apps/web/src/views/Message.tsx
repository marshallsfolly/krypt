import { createMemo, createResource, For, onCleanup, Show } from "solid-js";
import { haptic } from "../app/appearance";
import type { AppState, MessageRow } from "../app/state";
import { strings } from "../app/strings";
import { CHANGE_WINDOW_MS } from "../runtime/store";
import { Sheet } from "./Sheets";

/** The quick reactions; any emoji is allowed on the wire. */
export const REACTIONS = ["❤️", "👍", "😂", "😮", "😢", "🙏"];

/** Whether a row is this identity's own message (from this device or a
 * linked one). */
const ownedBy = (app: AppState, row: MessageRow) => row.mine || row.from === app.me;

/** Whether its sender can still change it (edit, delete for everyone). */
const changeable = (app: AppState, row: MessageRow) =>
  ownedBy(app, row) && !row.deleted && !row.system && Date.now() - row.at < CHANGE_WINDOW_MS;

/** A short line of what a message says, for quotes and previews. */
export function gist(row: MessageRow): string {
  if (row.deleted) return strings.messages.deleted;
  if (row.voice) return strings.voice.preview;
  if (row.file) return strings.files.preview(row.file.mediaType);
  return row.text;
}

/** Long-press (touch), right-click and a hover button open a message's
 * actions. Returns the handlers to spread on the message. */
export function pressFor(open: () => void) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let start: [number, number] | undefined;
  const cancel = () => {
    clearTimeout(timer);
    timer = undefined;
  };
  onCleanup(cancel);
  return {
    onPointerDown: (e: PointerEvent) => {
      if (e.pointerType === "mouse") return;
      start = [e.clientX, e.clientY];
      timer = setTimeout(() => {
        timer = undefined;
        haptic("tap");
        open();
      }, 450);
    },
    onPointerMove: (e: PointerEvent) => {
      if (start && Math.hypot(e.clientX - start[0], e.clientY - start[1]) > 8) cancel();
    },
    onPointerUp: cancel,
    onPointerCancel: cancel,
    onContextMenu: (e: MouseEvent) => {
      e.preventDefault();
      cancel();
      open();
    },
  };
}

/** What can be done with a message: react, reply, copy, edit, delete. */
export function MessageActions(props: {
  app: AppState;
  row: MessageRow;
  onReply: () => void;
  onEdit: () => void;
  onClose: () => void;
}) {
  const me = () => props.app.me;
  const mine = () => props.row.reactions?.[me()];
  const act = (work: () => unknown) => {
    void work();
    props.onClose();
  };
  return (
    <Sheet open title={strings.messages.actions} onClose={props.onClose}>
      <div class="stack">
        <Show when={!props.row.deleted}>
          <div class="reaction-row" role="group" aria-label={strings.messages.actions}>
            <For each={REACTIONS}>
              {(emoji) => (
                <button
                  class="reaction-pick press"
                  aria-pressed={mine() === emoji}
                  onClick={() =>
                    act(() => {
                      haptic("toggle");
                      return props.app.rt.react(props.row.conversation, props.row, mine() === emoji ? "" : emoji);
                    })
                  }
                >
                  {emoji}
                </button>
              )}
            </For>
          </div>
        </Show>
        <ul class="list action-list" role="list">
          <Show when={!props.row.deleted}>
            <li>
              <button class="list-item press" onClick={() => act(props.onReply)}>
                {strings.messages.reply}
              </button>
            </li>
          </Show>
          <Show when={props.row.text && !props.row.deleted}>
            <li>
              <button
                class="list-item press"
                onClick={() => act(() => navigator.clipboard?.writeText(props.row.text).then(() => haptic("success")))}
              >
                {strings.messages.copy}
              </button>
            </li>
          </Show>
          <Show when={changeable(props.app, props.row) && !props.row.file && props.row.text}>
            <li>
              <button class="list-item press" onClick={() => act(props.onEdit)}>
                {strings.messages.edit}
              </button>
            </li>
          </Show>
          <li>
            <button class="list-item press danger-text" onClick={() => act(() => props.app.rt.deleteForMe(props.row))}>
              {strings.messages.deleteForMe}
            </button>
          </li>
          <Show when={changeable(props.app, props.row) && props.row.mine}>
            <li>
              <button
                class="list-item press danger-text"
                onClick={() =>
                  act(() => {
                    haptic("hangup");
                    return props.app.rt.deleteForEveryone(props.row.conversation, props.row);
                  })
                }
              >
                {strings.messages.deleteForEveryone}
              </button>
            </li>
          </Show>
        </ul>
      </div>
    </Sheet>
  );
}

/** The message a reply answers: who wrote it and what it said. Tapping it
 * goes there. */
export function Quote(props: { app: AppState; id: string; onGo: (id: string) => void }) {
  const [target] = createResource(
    () => props.id,
    async (id) => props.app.thread(id.split(":")[0]!)?.find((r) => r.id === id) ?? (await props.app.rt.message(id)),
  );
  // Follows edits and deletions of the original as they arrive.
  const live = createMemo(() => props.app.thread(props.id.split(":")[0]!)?.find((r) => r.id === props.id) ?? target());
  return (
    <button class="msg-quote press" onClick={() => live() && props.onGo(props.id)}>
      <Show when={live()} fallback={<span class="caption muted">{strings.messages.originalGone}</span>}>
        {(row) => (
          <>
            <span class="label">{row().mine ? strings.you : props.app.name(row().from!)}</span>
            <span class="caption truncate">{gist(row())}</span>
          </>
        )}
      </Show>
    </button>
  );
}

/** Reactions under a message: each emoji once, with how many chose it. */
export function Reactions(props: { app: AppState; row: MessageRow }) {
  const groups = () => {
    const by = new Map<string, string[]>();
    for (const [identity, emoji] of Object.entries(props.row.reactions ?? {})) by.set(emoji, [...(by.get(emoji) ?? []), identity]);
    return [...by];
  };
  return (
    <Show when={groups().length > 0}>
      <div class="reactions">
        <For each={groups()}>
          {([emoji, who]) => {
            const mine = () => who.includes(props.app.me);
            const names = () => who.map((i) => (i === props.app.me ? strings.you : props.app.name(i))).join(", ");
            return (
              <button
                class="reaction press"
                classList={{ mine: mine() }}
                aria-label={strings.messages.reaction(emoji, names())}
                onClick={() => {
                  haptic("toggle");
                  void props.app.rt.react(props.row.conversation, props.row, mine() ? "" : emoji);
                }}
              >
                {emoji}
                <Show when={who.length > 1}>
                  <span class="meta">{who.length}</span>
                </Show>
              </button>
            );
          }}
        </For>
      </div>
    </Show>
  );
}

/** "Sent", then "Read" (one-to-one) or "Read by n" (a group). */
export function readState(app: AppState, row: MessageRow, group: boolean): string {
  if (row.state !== "sent") return strings.queued;
  const readers = app.receipts.readBy(row);
  if (readers.length === 0) return strings.sent;
  return group ? strings.messages.readBy(readers.length) : strings.messages.read;
}

