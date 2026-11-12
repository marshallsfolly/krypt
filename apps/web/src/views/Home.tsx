import { createResource, createSignal, For, Show } from "solid-js";
import { haptic } from "../app/appearance";
import { Icon } from "../app/icons";
import type { AppState } from "../app/state";
import { strings } from "../app/strings";
import { Avatar } from "./Avatar";
import type { SheetName } from "../App";
import { gist } from "./Message";
import { fold } from "../runtime/store";
import type { MessageRow } from "../app/state";

/** `text` with the first match of `query` marked (case-insensitively). */
function Marked(props: { text: string; query: string }) {
  const at = () => props.text.toLowerCase().indexOf(props.query.trim().toLowerCase());
  return (
    <Show when={at() >= 0 && props.query.trim()} fallback={<>{props.text}</>}>
      {props.text.slice(Math.max(0, at() - 24), at())}
      <mark>{props.text.slice(at(), at() + props.query.trim().length)}</mark>
      {props.text.slice(at() + props.query.trim().length)}
    </Show>
  );
}

function when(ms: number): string {
  const d = new Date(ms);
  const today = new Date();
  return d.toDateString() === today.toDateString()
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}

export function Home(props: {
  app: AppState;
  current?: string;
  onOpen: (id: string, focus?: string) => void;
  onSheet: (sheet: SheetName) => void;
  onSettings: () => void;
}) {
  const [showRequests, setShowRequests] = createSignal(false);
  const [showArchived, setShowArchived] = createSignal(false);
  const [searching, setSearching] = createSignal(false);
  const [query, setQuery] = createSignal("");
  const [typed, setTyped] = createSignal("");
  let wait: ReturnType<typeof setTimeout> | undefined;
  const [found] = createResource(
    () => (searching() && query().trim().length >= 2 ? query() : undefined),
    (q) => props.app.search(q),
  );
  const chatsFound = () => {
    const q = fold(query().trim());
    if (q.length < 2) return [];
    return [...props.app.conversations(), ...props.app.requests()].filter((c) => fold(props.app.title(c)).includes(q));
  };
  const listed = () => props.app.conversations().filter((c) => props.app.isArchived(c.id) === showArchived());
  const archivedCount = () => props.app.conversations().filter((c) => props.app.isArchived(c.id)).length;
  const titleOf = (row: MessageRow) => {
    const c = props.app.conversation(row.conversation);
    return c ? props.app.title(c) : "";
  };
  const closeSearch = () => {
    setSearching(false);
    setQuery("");
    setTyped("");
  };
  const preview = (id: string): string => {
    const row = props.app.last(id);
    if (!row) return strings.encrypted;
    if (row.system) return strings.encrypted;
    const text = gist(row);
    return row.mine ? `${strings.you}: ${text}` : text;
  };

  return (
    <section class="pane pane-list" aria-label={strings.chats}>
      <header class="bar">
        <Show
          when={searching()}
          fallback={<h1 class="title">{showArchived() ? strings.archive.title : strings.chats}</h1>}
        >
          <input
            class="body search-input"
            type="search"
            placeholder={strings.search.placeholder}
            aria-label={strings.search.placeholder}
            value={typed()}
            ref={(el) => queueMicrotask(() => el.focus())}
            onInput={(e) => {
              const value = e.currentTarget.value;
              setTyped(value);
              clearTimeout(wait);
              wait = setTimeout(() => setQuery(value), 200);
            }}
            onKeyDown={(e) => e.key === "Escape" && closeSearch()}
          />
        </Show>
        <div class="bar-actions">
          <button
            class="icon-btn"
            onClick={() => (searching() ? closeSearch() : setSearching(true))}
            aria-label={searching() ? strings.search.close : strings.search.open}
          >
            <Icon name={searching() ? "close" : "search"} />
          </button>
          <button class="icon-btn" onClick={() => props.onSheet("myCard")} aria-label={strings.myCard}>
            <Icon name="card" />
          </button>
          <button class="icon-btn" onClick={props.onSettings} aria-label={strings.settings}>
            <Icon name="gear" />
          </button>
        </div>
      </header>
      <div class="scroll">
        <Show when={searching()}>
          <div class="search-results">
            <Show when={query().trim().length >= 2} fallback={<p class="caption muted pad">{strings.search.tooShort}</p>}>
              <Show when={chatsFound().length > 0}>
                <h2 class="label pad">{strings.search.chats}</h2>
                <ul class="list" role="list">
                  <For each={chatsFound()}>
                    {(c) => (
                      <li>
                        <button class="list-item press" onClick={() => props.onOpen(c.id)}>
                          <Avatar
                            app={props.app}
                            identity={props.app.others(c)[0]}
                            group={props.app.isGroup(c) ? { id: c.id, title: props.app.title(c) } : undefined}
                          />
                          <span class="list-text">
                            <span class="headline truncate">
                              <Marked text={props.app.title(c)} query={query()} />
                            </span>
                          </span>
                        </button>
                      </li>
                    )}
                  </For>
                </ul>
              </Show>
              <Show when={(found() ?? []).length > 0}>
                <h2 class="label pad">{strings.search.messages}</h2>
                <ul class="list" role="list">
                  <For each={found()}>
                    {(row) => (
                      <li>
                        <button class="list-item press search-hit" onClick={() => props.onOpen(row.conversation, row.id)}>
                          <span class="list-text">
                            <span class="list-top">
                              <span class="headline truncate">{titleOf(row)}</span>
                              <span class="meta">{when(row.at)}</span>
                            </span>
                            <span class="caption truncate">
                              <Show when={row.mine}>{strings.you}: </Show>
                              <Marked text={row.text} query={query()} />
                            </span>
                          </span>
                        </button>
                      </li>
                    )}
                  </For>
                </ul>
              </Show>
              <Show when={!found.loading && (found() ?? []).length === 0 && chatsFound().length === 0}>
                <p class="caption muted pad">{strings.search.none}</p>
              </Show>
            </Show>
          </div>
        </Show>
        <div hidden={searching()}>
        <For each={props.app.pendingJoins()}>
          {(group) => (
            <p class="caption muted pad pending-join" role="status">
              {strings.invite.waiting(group)}
            </p>
          )}
        </For>
        <Show when={props.app.requests().length > 0}>
          <button
            class="requests press"
            aria-expanded={showRequests()}
            onClick={() => {
              haptic("tap");
              setShowRequests(!showRequests());
            }}
          >
            <span class="headline">{strings.requests.title}</span>
            <span class="chip">{strings.requests.count(props.app.requests().length)}</span>
          </button>
          <Show when={showRequests()}>
            <ul class="list requests-list" role="list" aria-label={strings.requests.title}>
              <For each={props.app.requests()}>
                {(c) => (
                  <li>
                    <button
                      class="list-item press"
                      classList={{ current: props.current === c.id }}
                      onClick={() => props.onOpen(c.id)}
                    >
                      <Avatar app={props.app} identity={props.app.others(c)[0]} />
                      <span class="list-text">
                        <span class="list-top">
                          <span class="headline truncate">{props.app.title(c)}</span>
                        </span>
                        <span class="caption muted truncate">{preview(c.id)}</span>
                      </span>
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </Show>
        <Show
          when={props.app.conversations().length > 0 || props.app.requests().length > 0}
          fallback={
            <div class="empty">
              <p class="headline">{strings.noChats}</p>
              <p class="muted">{strings.noChatsHint}</p>
              <div class="row-actions">
                <button class="btn" onClick={() => props.onSheet("newChat")}>
                  {strings.newChat}
                </button>
                <button class="btn ghost" onClick={() => props.onSheet("myCard")}>
                  {strings.myCard}
                </button>
              </div>
            </div>
          }
        >
          <Show when={showArchived()}>
            <button class="requests press" aria-expanded="true" onClick={() => setShowArchived(false)}>
              <span class="headline">{strings.archive.title}</span>
              <Icon name="close" size={18} />
            </button>
            <p class="caption muted pad">{strings.archive.hint}</p>
          </Show>
          <ul class="list" role="list">
            <For each={listed()}>
              {(c) => (
                <li>
                  <button
                    class="list-item press"
                    classList={{ current: props.current === c.id, inactive: !c.active }}
                    onClick={() => props.onOpen(c.id)}
                  >
                    <Avatar
                      app={props.app}
                      identity={props.app.others(c)[0]}
                      group={props.app.isGroup(c) ? { id: c.id, title: props.app.title(c) } : undefined}
                    />
                    <span class="list-text">
                      <span class="list-top">
                        <span class="headline truncate">{props.app.title(c)}</span>
                        <Show when={props.app.isMuted(c.id)}>
                          <Icon name="bellOff" size={14} label={strings.mute.forever} />
                        </Show>
                        <Show when={!props.app.isGroup(c) && props.app.others(c).some((i) => props.app.presence.isOnline(i))}>
                          <span class="online-dot" role="img" aria-label={strings.presence.online} />
                        </Show>
                        <Show when={props.app.last(c.id)}>
                          {(row) => <span class="meta">{when(row().at)}</span>}
                        </Show>
                      </span>
                      <Show
                        when={props.app.presence.typingIn(c.id).length > 0}
                        fallback={<span class="caption muted truncate">{preview(c.id)}</span>}
                      >
                        <span class="caption truncate typing-text">
                          {props.app.isGroup(c)
                            ? strings.presence.typingIn(props.app.presence.typingIn(c.id).map((i) => props.app.name(i)))
                            : strings.presence.typing}
                        </span>
                      </Show>
                    </span>
                  </button>
                </li>
              )}
            </For>
          </ul>
          <Show when={!showArchived() && archivedCount() > 0}>
            <button class="requests press archived-row" onClick={() => setShowArchived(true)}>
              <Icon name="archive" size={18} />
              <span class="headline">{strings.archive.archived(archivedCount())}</span>
            </button>
          </Show>
        </Show>
        </div>
      </div>
      <Show when={props.app.conversations().length > 0 && !searching()}>
        <button class="fab press" onClick={() => props.onSheet("newChat")} aria-label={strings.newChat}>
          <Icon name="plus" size={26} />
        </button>
      </Show>
    </section>
  );
}
