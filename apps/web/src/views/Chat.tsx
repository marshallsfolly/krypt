import { createEffect, createResource, createSignal, For, Match, on, onCleanup, Show, Switch } from "solid-js";
import { haptic } from "../app/appearance";
import { Icon } from "../app/icons";
import type { AppState, MessageRow } from "../app/state";
import { strings } from "../app/strings";
import { CallFull, RelayUnavailable } from "../runtime/call";
import { FileTooLarge } from "../runtime/device";
import { shown } from "../runtime/files";
import { NotScrubbed, safeName } from "../runtime/media";
import { gist, MessageActions, pressFor, Quote, Reactions, readState } from "./Message";
import { Recorder, VoiceBubble } from "./Voice";

const time = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/** A `blob:` URL for some bytes, revoked when its owner goes away. */
function useUrl(source: () => Blob | undefined): () => string | undefined {
  const [url, setUrl] = createSignal<string>();
  createEffect(() => {
    const blob = source();
    if (!blob) return setUrl(undefined);
    const next = URL.createObjectURL(blob);
    setUrl(next);
    onCleanup(() => URL.revokeObjectURL(next));
  });
  return url;
}

/** Width over height for layout before anything loads; the sender says,
 * so it is clamped. */
function aspect(width: number, height: number): string {
  if (!width || !height) return "4 / 3";
  const ratio = Math.min(Math.max(width / height, 0.4), 2.5);
  return `${ratio}`;
}

function FileBubble(props: { app: AppState; row: MessageRow; onView: (row: MessageRow) => void }) {
  const file = () => props.row.file!;
  const kind = () => shown(file().mediaType);
  const [blob] = createResource(
    () => (file().state === "ready" ? file().id : undefined),
    (id) => props.app.rt.file(id),
  );
  const url = useUrl(() => blob() ?? undefined);
  const thumb = useUrl(() =>
    file().thumbnail.length > 0 ? new Blob([file().thumbnail as Uint8Array<ArrayBuffer>], { type: "image/jpeg" }) : undefined,
  );
  const progress = () => props.app.progress(file().id);
  const percent = () => Math.round((progress() ?? 0) * 100);
  const download = () => void props.app.rt.download(props.row);

  const status = () => {
    const f = file();
    if (f.state === "uploading") return progress() === undefined ? strings.files.preparing : strings.files.uploading(percent());
    if (progress() !== undefined) return strings.files.downloading(percent());
    if (f.state === "failed") return props.row.mine ? strings.files.sendFailed : strings.files.failed;
    if (f.state === "damaged") return strings.files.damaged;
    if (f.state === "expired") return strings.files.expired;
    return undefined;
  };
  const retry = () => (props.row.mine ? void props.app.rt.retryUpload(props.row) : download());

  return (
    <div class="msg-file" classList={{ media: kind() !== "file" }} data-state={file().state}>
      <Switch>
        <Match when={kind() === "image"}>
          <button
            class="file-media press"
            style={{ "aspect-ratio": aspect(file().width, file().height) }}
            aria-label={`${strings.files.open} ${file().name}`}
            onClick={() => (url() ? props.onView(props.row) : file().state === "remote" ? download() : undefined)}
          >
            <Show when={url() ?? thumb()}>{(src) => <img src={src()} alt="" draggable={false} />}</Show>
            <Show when={!url() && file().state === "remote" && progress() === undefined}>
              <span class="file-badge label">
                <Icon name="download" size={16} /> {strings.files.size(file().size)}
              </span>
            </Show>
          </button>
        </Match>
        <Match when={kind() === "video"}>
          <Show
            when={url()}
            fallback={
              <button
                class="file-media press"
                style={{ "aspect-ratio": aspect(file().width, file().height) }}
                aria-label={`${strings.files.download} ${file().name}`}
                onClick={() => (file().state === "remote" ? download() : undefined)}
              >
                <Show when={thumb()}>{(src) => <img src={src()} alt="" draggable={false} />}</Show>
                <span class="file-badge label">
                  <Icon name={file().state === "remote" ? "download" : "play"} size={16} /> {strings.files.size(file().size)}
                </span>
              </button>
            }
          >
            {(src) => (
              <video
                class="file-media"
                style={{ "aspect-ratio": aspect(file().width, file().height) }}
                src={src()}
                poster={thumb()}
                controls
                playsinline
                preload="metadata"
              />
            )}
          </Show>
        </Match>
        <Match when={kind() === "file"}>
          <div class="file-card">
            <Icon name="file" />
            <span class="file-card-text">
              <span class="body truncate">{file().name}</span>
              <span class="caption muted">{strings.files.size(file().size)}</span>
            </span>
            <Show
              when={url()}
              fallback={
                <Show when={file().state === "remote" && progress() === undefined}>
                  <button class="icon-btn" onClick={download} aria-label={`${strings.files.download} ${file().name}`}>
                    <Icon name="download" />
                  </button>
                </Show>
              }
            >
              {(href) => (
                <a class="icon-btn" href={href()} download={safeName(file().name)} aria-label={`${strings.files.save} ${file().name}`}>
                  <Icon name="download" />
                </a>
              )}
            </Show>
          </div>
        </Match>
      </Switch>
      <Show when={status()}>
        {(text) => (
          <span class="file-status caption">
            <Show when={progress() !== undefined}>
              <span class="file-progress" style={{ "--progress": `${percent()}%` }} />
            </Show>
            {text()}
            <Show when={file().state === "failed"}>
              <button class="link" onClick={retry}>
                {strings.files.retry}
              </button>
            </Show>
          </span>
        )}
      </Show>
    </div>
  );
}

/** A photo, full size, with a way to save it. */
function Viewer(props: { app: AppState; row: MessageRow; onClose: () => void }) {
  let dialog!: HTMLDialogElement;
  const [blob] = createResource(() => props.row.file!.id, (id) => props.app.rt.file(id));
  const url = useUrl(() => blob() ?? undefined);
  createEffect(() => dialog.showModal());
  return (
    <dialog ref={dialog} class="viewer" onClose={props.onClose} onClick={(e) => e.target === dialog && dialog.close()}>
      <Show when={url()}>{(src) => <img src={src()} alt={props.row.file!.name} />}</Show>
      <div class="viewer-bar">
        <Show when={url()}>
          {(href) => (
            <a class="icon-btn" href={href()} download={safeName(props.row.file!.name)} aria-label={strings.files.save}>
              <Icon name="download" />
            </a>
          )}
        </Show>
        <button class="icon-btn" onClick={() => dialog.close()} aria-label={strings.files.close}>
          <Icon name="close" />
        </button>
      </div>
    </dialog>
  );
}

function systemText(app: AppState, row: MessageRow): string {
  const s = row.system!;
  const names = s.identities.filter((i) => i !== app.me).map(app.name).join(", ");
  switch (s.event) {
    case "call":
      return strings.system.call(s.call!);
    case "timer":
      return strings.system.timer(app.name(s.identities[0] ?? app.me), s.seconds ?? 0);
    case "renamed":
      return strings.system.renamed(app.name(s.identities[0] ?? app.me), s.name ?? "");
    case "membersAdded":
      return strings.system.membersAdded(names);
    case "membersRemoved":
      return s.by
        ? strings.system.membersRemovedBy(s.by === app.me ? strings.you : app.name(s.by), names || strings.you.toLowerCase())
        : strings.system.membersRemoved(names);
    case "inviteFailed":
      return strings.system.inviteFailed(names);
    case "rules": {
      const r = s.rules!;
      const who = (ids: string[]) => ids.map((i) => (i === app.me ? strings.you.toLowerCase() : app.name(i))).join(", ");
      return strings.system.rules(app.name(s.identities[0] ?? app.me), who(r.added), who(r.removed), r.add, r.edit, r.link);
    }
    default:
      return strings.system[s.event]();
  }
}

export function Chat(props: { app: AppState; id: string; focus?: string; onBack: () => void; onInfo: () => void }) {
  const [draft, setDraft] = createSignal("");
  const [viewing, setViewing] = createSignal<MessageRow>();
  /** The message whose actions are open, the one being answered, and the
   * one being edited. */
  const [acting, setActing] = createSignal<MessageRow>();
  const [replying, setReplying] = createSignal<MessageRow>();
  const [editing, setEditing] = createSignal<MessageRow>();
  const [recording, setRecording] = createSignal(false);
  const [notice, setNotice] = createSignal<string>();
  let list!: HTMLDivElement;
  let input!: HTMLTextAreaElement;
  let picker!: HTMLInputElement;
  let noticeTimer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => clearTimeout(noticeTimer));

  const tell = (text: string) => {
    setNotice(text);
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => setNotice(undefined), 6_000);
  };

  const attach = async (files: Iterable<File>) => {
    if (!conversation()?.active) return;
    for (const file of files) {
      haptic("send");
      try {
        await props.app.rt.sendFile(props.id, file);
      } catch (error) {
        haptic("cancel");
        tell(
          error instanceof FileTooLarge
            ? strings.files.tooLarge
            : error instanceof NotScrubbed
              ? strings.files.notScrubbed
              : strings.files.sendFailed,
        );
      }
    }
  };

  const conversation = () => props.app.conversation(props.id);
  const rows = () => props.app.thread(props.id) ?? [];
  const request = () => props.app.isRequest(props.id);
  const timer = () => props.app.timer(props.id);
  // Disappearing messages start their clock once they are on screen, and
  // read receipts go out. A request's messages count as seen only once it
  // is accepted.
  createEffect(() => {
    const all = rows();
    if (request() || document.visibilityState !== "visible") return;
    props.app.receipts.seen(props.id, all);
    const unseen = all.filter((r) => r.expires && r.deleteAt === undefined);
    if (unseen.length > 0) void props.app.rt.shown(unseen);
  });
  const onVisible = () => {
    if (document.visibilityState !== "visible" || request()) return;
    props.app.receipts.seen(props.id, rows());
    const unseen = rows().filter((r) => r.expires && r.deleteAt === undefined);
    if (unseen.length > 0) void props.app.rt.shown(unseen);
  };
  document.addEventListener("visibilitychange", onVisible);
  onCleanup(() => document.removeEventListener("visibilitychange", onVisible));
  /** The one other person, in a one-to-one conversation: who a call rings. */
  /** Who a call rings: everyone else here (one person, or a group). */
  const callable = () => {
    const c = conversation();
    return c?.active && !request() ? props.app.others(c) : [];
  };
  /** A group call running here, which this device can join. */
  const running = () => (callable().length > 1 ? props.app.calls.activeIn(props.id) : undefined);
  const call = (video: boolean) => {
    if (callable().length === 0) return;
    haptic("tap");
    props.app.calls.start(props.id, callable(), video).catch((error: unknown) => {
      haptic("cancel");
      tell(
        error instanceof CallFull
          ? strings.calls.full
          : error instanceof RelayUnavailable
            ? strings.calls.noRelay
            : strings.calls.noMedia,
      );
    });
  };
  const verified = () => {
    const c = conversation();
    const others = c ? props.app.others(c) : [];
    return others.length > 0 && others.every((i) => props.app.people[i]?.verified);
  };

  const typers = () => props.app.presence.typingIn(props.id);
  /** Typing, then online, in place of the encryption state while there is
   * any (the shield stays). */
  const presence = () => {
    const c = conversation();
    if (!c) return undefined;
    const names = typers().map((i) => props.app.name(i));
    const group = props.app.isGroup(c);
    if (names.length > 0) return group ? strings.presence.typingIn(names) : strings.presence.typing;
    const online = props.app.others(c).filter((i) => props.app.presence.isOnline(i)).length;
    if (online === 0) return undefined;
    return group ? strings.presence.onlineCount(online) : strings.presence.online;
  };

  // Keep the newest message (or someone typing) in view.
  createEffect(
    on(
      () => [rows().length, typers().length > 0],
      () => queueMicrotask(() => list.scrollTo({ top: list.scrollHeight })),
    ),
  );
  // Leaving a chat (or switching to another) ends typing in it. The id is
  // kept here: once this view has left the chat, reading it would throw.
  let typingIn = props.id;
  createEffect(
    on(
      () => props.id,
      (id) => {
        if (id !== typingIn) props.app.presence.stopTyping(typingIn);
        typingIn = id;
      },
      { defer: true },
    ),
  );
  onCleanup(() => props.app.presence.stopTyping(typingIn));
  // A message arriving in the open chat is felt; elsewhere it is not.
  createEffect(
    on(props.app.arrivals, (row) => {
      if (row?.conversation === props.id) haptic("receive");
    }, { defer: true }),
  );

  const send = async () => {
    const text = draft().trim();
    if (!text || !conversation()?.active) return;
    const [answer, change] = [replying(), editing()];
    setDraft("");
    setReplying(undefined);
    setEditing(undefined);
    props.app.presence.stopTyping(props.id);
    input.style.height = "";
    haptic("send");
    if (change) {
      if (text !== change.text) await props.app.rt.edit(props.id, change, text);
    } else if (answer) await props.app.rt.reply(props.id, answer, text);
    else await props.app.rt.send(props.id, text);
  };

  // Opened on a message (from search): go to it once it is on screen.
  createEffect(
    on(
      () => [props.focus, rows().length] as const,
      ([focus]) => {
        if (focus && rows().some((r) => r.id === focus)) setTimeout(() => goTo(focus), 50);
      },
    ),
  );

  /** Scrolls to a message and marks it for a moment. */
  const goTo = (id: string) => {
    const el = list.querySelector<HTMLElement>(`[data-id="${CSS.escape(id)}"]`);
    if (!el) return;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    el.classList.remove("flash");
    void el.offsetWidth;
    el.classList.add("flash");
  };
  const reply = (row: MessageRow) => {
    setEditing(undefined);
    setReplying(row);
    input.focus();
  };
  const edit = (row: MessageRow) => {
    setReplying(undefined);
    setEditing(row);
    setDraft(row.text);
    queueMicrotask(() => {
      grow();
      input.focus();
    });
  };
  const cancelContext = () => {
    if (editing()) setDraft("");
    setReplying(undefined);
    setEditing(undefined);
  };

  const grow = () => {
    input.style.height = "";
    input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
  };

  return (
    <section class="pane pane-chat" aria-label={conversation() ? props.app.title(conversation()!) : ""}>
      <header class="bar">
        <button class="icon-btn back" onClick={props.onBack} aria-label={strings.back}>
          <Icon name="back" />
        </button>
        <button class="bar-title press" onClick={props.onInfo}>
          <span class="headline truncate">{conversation() ? props.app.title(conversation()!) : ""}</span>
          <span class="label status" classList={{ ok: verified(), live: !!presence() }}>
            <Icon name={verified() ? "check" : "shield"} size={13} />
            {presence() ?? (verified() ? strings.verified : strings.encrypted)}
            <Show when={timer() > 0}>
              <span class="status-timer" aria-label={`${strings.timer.title}: ${strings.timer.label(timer())}`}>
                <Icon name="timer" size={13} />
                {strings.timer.short(timer())}
              </span>
            </Show>
          </span>
        </button>
        <Show when={callable().length > 0}>
          <Show
            when={running()}
            fallback={
              <>
                <button class="icon-btn" onClick={() => call(false)} aria-label={strings.calls.voice} disabled={!!props.app.calls.current()}>
                  <Icon name="phone" />
                </button>
                <button class="icon-btn" onClick={() => call(true)} aria-label={strings.calls.video} disabled={!!props.app.calls.current()}>
                  <Icon name="video" />
                </button>
              </>
            }
          >
            {(active) => (
              <button
                class="chip press join-call"
                onClick={() => call(active().video)}
                aria-label={strings.calls.joinCall(active().video)}
                disabled={!!props.app.calls.current()}
              >
                <Icon name={active().video ? "video" : "phone"} size={16} />
                {strings.calls.join}
              </button>
            )}
          </Show>
        </Show>
        <button class="icon-btn" onClick={props.onInfo} aria-label={strings.info}>
          <Icon name="info" />
        </button>
      </header>
      <div class="scroll messages" ref={list} role="log" aria-live="polite">
        <For each={rows()}>
          {(row, i) => (
            <Show
              when={!row.system}
              fallback={
                <p class="system caption muted" classList={{ enter: props.app.fresh(row.id) }}>
                  {systemText(props.app, row)}
                </p>
              }
            >
              <article
                class="msg"
                data-id={row.id}
                classList={{
                  enter: props.app.fresh(row.id),
                  mine: row.mine,
                  // Consecutive messages from one sender group together.
                  grouped: rows()[i() - 1]?.from === row.from && rows()[i() - 1]?.mine === row.mine && !rows()[i() - 1]?.system,
                }}
                {...pressFor(() => setActing(row))}
              >
                <span class="msg-meta meta">
                  <span class="msg-from">{row.mine ? strings.you : props.app.name(row.from!)}</span>
                  <time>{time(row.at)}</time>
                  <Show when={row.edited && !row.deleted}>
                    <span class="msg-edited">{strings.messages.edited}</span>
                  </Show>
                  <button class="msg-more icon-btn" aria-label={strings.messages.more} onClick={() => setActing(row)}>
                    <Icon name="more" size={16} />
                  </button>
                </span>
                <Show
                  when={!row.deleted}
                  fallback={<div class="msg-body body deleted">{strings.messages.deleted}</div>}
                >
                  <Switch
                    fallback={
                      <div class="msg-body body">
                        <Show when={row.replyTo}>{(id) => <Quote app={props.app} id={id()} onGo={goTo} />}</Show>
                        {row.text}
                      </div>
                    }
                  >
                    <Match when={row.voice && row.file}>
                      <VoiceBubble app={props.app} row={row} />
                    </Match>
                    <Match when={row.file}>
                      <FileBubble app={props.app} row={row} onView={setViewing} />
                    </Match>
                  </Switch>
                </Show>
                <Reactions app={props.app} row={row} />
                <Show when={row.mine}>
                  <span class="msg-state meta">
                    <Show when={row.expires}>
                      <Icon name="timer" size={11} label={strings.timer.title} />{" "}
                    </Show>
                    {readState(props.app, row, !!conversation() && props.app.isGroup(conversation()!))}
                  </span>
                </Show>
                <Show when={!row.mine && row.expires}>
                  <span class="msg-state meta">
                    <Icon name="timer" size={11} label={strings.timer.title} />
                  </span>
                </Show>
              </article>
            </Show>
          )}
        </For>
        <Show when={typers().length > 0}>
          <div class="typing" role="status" aria-label={presence()}>
            <span />
            <span />
            <span />
          </div>
        </Show>
      </div>
      <Show when={request() && conversation()}>
        {(c) => {
          const them = () => props.app.others(c());
          return (
            <div class="request-bar">
              <p class="caption muted">{strings.requests.hint(them().map(props.app.name).join(", "))}</p>
              <div class="row-actions">
                <button
                  class="btn ghost danger-text"
                  onClick={() => {
                    haptic("tap");
                    void Promise.all(them().map((who) => props.app.block(who, props.id))).then(props.onBack);
                  }}
                >
                  {strings.requests.block}
                </button>
                <button
                  class="btn ghost"
                  onClick={() => {
                    haptic("tap");
                    void props.app.deleteChat(props.id).then(props.onBack);
                  }}
                >
                  {strings.requests.delete}
                </button>
                <button
                  class="btn"
                  onClick={() => {
                    haptic("success");
                    void props.app.accept(props.id);
                  }}
                >
                  {strings.requests.accept}
                </button>
              </div>
            </div>
          );
        }}
      </Show>
      <Show
        when={conversation()?.active !== false && !request()}
        fallback={
          <Show when={!request()}>
            <p class="composer-note caption muted">{strings.inactive}</p>
          </Show>
        }
      >
        <Show when={notice()}>
          {(text) => (
            <p class="composer-note caption" role="status">
              {text()}
            </p>
          )}
        </Show>
        <Show when={replying() ?? editing()}>
          {(row) => (
            <div class="composer-context">
              <span class="composer-context-text">
                <span class="label">
                  {editing() ? strings.messages.editing : strings.messages.replyingTo(row().mine ? strings.you : props.app.name(row().from!))}
                </span>
                <Show when={replying()}>
                  <span class="caption truncate">{gist(row())}</span>
                </Show>
              </span>
              <button class="icon-btn" type="button" onClick={cancelContext} aria-label={strings.messages.cancel}>
                <Icon name="close" size={18} />
              </button>
            </div>
          )}
        </Show>
        <Show
          when={!recording()}
          fallback={
            <Recorder
              onSend={(blob, ms, wave) => {
                setRecording(false);
                void props.app.rt.sendVoice(props.id, blob, ms, wave).catch((error: unknown) => {
                  haptic("cancel");
                  tell(error instanceof NotScrubbed ? strings.files.notScrubbed : strings.voice.failed);
                });
              }}
              onCancel={() => setRecording(false)}
              onError={(message) => {
                setRecording(false);
                tell(message);
              }}
            />
          }
        >
          <form
            class="composer"
            onSubmit={(e) => {
              e.preventDefault();
              void send();
            }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              if (e.dataTransfer?.files.length) void attach(e.dataTransfer.files);
            }}
          >
            <input
              ref={picker}
              type="file"
              multiple
              hidden
              onChange={(e) => {
                const files = [...(e.currentTarget.files ?? [])];
                e.currentTarget.value = "";
                void attach(files);
              }}
            />
            <button class="icon-btn attach" type="button" onClick={() => picker.click()} aria-label={strings.files.attach}>
              <Icon name="attach" />
            </button>
            <textarea
              ref={input}
              class="body"
              rows="1"
              placeholder={strings.message}
              aria-label={strings.message}
              value={draft()}
              onInput={(e) => {
                setDraft(e.currentTarget.value);
                grow();
                if (e.currentTarget.value.trim()) props.app.presence.typed(props.id);
                else props.app.presence.stopTyping(props.id);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
                  e.preventDefault();
                  void send();
                }
              }}
              onPaste={(e) => {
                const files = [...(e.clipboardData?.files ?? [])];
                if (files.length === 0) return;
                e.preventDefault();
                void attach(files);
              }}
            />
            <Show
              when={draft().trim() || editing()}
              fallback={
                <button
                  class="send press"
                  type="button"
                  aria-label={strings.voice.record}
                  onClick={() => {
                    setReplying(undefined);
                    setRecording(true);
                  }}
                >
                  <Icon name="mic" />
                </button>
              }
            >
              <button class="send press" type="submit" disabled={!draft().trim()} aria-label={strings.send}>
                <Icon name="send" />
              </button>
            </Show>
          </form>
        </Show>
      </Show>
      <Show when={viewing()}>{(row) => <Viewer app={props.app} row={row()} onClose={() => setViewing(undefined)} />}</Show>
      <Show when={acting()}>
        {(row) => (
          <MessageActions
            app={props.app}
            row={row()}
            onReply={() => reply(row())}
            onEdit={() => edit(row())}
            onClose={() => setActing(undefined)}
          />
        )}
      </Show>
    </section>
  );
}
