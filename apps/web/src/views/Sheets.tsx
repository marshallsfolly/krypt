import { createEffect, createResource, createSignal, For, type JSX, Show } from "solid-js";
import { haptic } from "../app/appearance";
import { Icon } from "../app/icons";
import { mailboxBase, webOrigin } from "../app/platform";
import type { AppState } from "../app/state";
import { strings, TIMERS } from "../app/strings";
import { cardIdentity, fingerprintOf, isContactCard, safetyNumber } from "../runtime/device";
import { lookup, normalize } from "../runtime/passkey";
import { Avatar } from "./Avatar";
import { Qr } from "./Qr";
import { canScan, Scanner } from "./Scanner";

/** A modal sheet on the native <dialog>: focus is trapped, Escape closes. */
export function Sheet(props: { open: boolean; title: string; onClose: () => void; children: JSX.Element }) {
  let dialog!: HTMLDialogElement;
  createEffect(() => {
    if (props.open && !dialog.open) dialog.showModal();
    if (!props.open && dialog.open) dialog.close();
  });
  return (
    <dialog
      ref={dialog}
      class="sheet"
      aria-label={props.title}
      onClose={props.onClose}
      onClick={(e) => {
        if (e.target === dialog) props.onClose();
      }}
    >
      <div class="sheet-body">
        <span class="sheet-handle" aria-hidden="true" />
        <header class="sheet-head">
          <h2 class="title">{props.title}</h2>
          <button class="icon-btn" onClick={props.onClose} aria-label="Close">
            <Icon name="close" />
          </button>
        </header>
        <Show when={props.open}>{props.children}</Show>
      </div>
    </dialog>
  );
}

/** A named group, made from people this device is already connected with:
 * a group is no place to meet someone new. */
function NewGroup(props: { app: AppState; onStarted: (id: string) => void }) {
  const [name, setName] = createSignal("");
  const [picked, setPicked] = createSignal<string[]>([]);
  const [busy, setBusy] = createSignal(false);
  const contacts = () => props.app.contacts().sort((a, b) => props.app.name(a.identity).localeCompare(props.app.name(b.identity)));

  const create = async (e: Event) => {
    e.preventDefault();
    if (busy() || picked().length === 0 || name().length > 64) return;
    setBusy(true);
    try {
      const id = await props.app.startGroup(picked(), name().trim());
      haptic("success");
      props.onStarted(id);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Show when={contacts().length > 0} fallback={<p class="body muted">{strings.groups.noPeople}</p>}>
      <form class="stack" onSubmit={create}>
        <label class="field">
          <span class="label">{strings.groups.name}</span>
          <input
            class="body"
            placeholder={strings.groups.namePlaceholder}
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            maxLength={64}
          />
        </label>
        <span class="label">{strings.groups.people}</span>
        <ul class="list pick-list" role="list">
          <For each={contacts()}>
            {(contact) => (
              <li>
                <label class="member pick">
                  <Avatar app={props.app} identity={contact.identity} />
                  <span class="list-text">
                    <span class="headline truncate">{props.app.name(contact.identity)}</span>
                    <span class="meta muted">{fingerprintOf(contact.identity)}</span>
                  </span>
                  <input
                    type="checkbox"
                    class="check"
                    checked={picked().includes(contact.card)}
                    onChange={(e) => {
                      haptic("toggle");
                      setPicked(e.currentTarget.checked ? [...picked(), contact.card] : picked().filter((c) => c !== contact.card));
                    }}
                  />
                </label>
              </li>
            )}
          </For>
        </ul>
        <button class="btn wide" type="submit" disabled={picked().length === 0 || busy()}>
          {strings.groups.create(picked().length)}
        </button>
      </form>
    </Show>
  );
}

export function NewChatSheet(props: {
  app: AppState;
  open: boolean;
  initial?: string;
  onClose: () => void;
  onStarted: (id: string) => void;
}) {
  const [group, setGroup] = createSignal(false);
  const [card, setCard] = createSignal("");
  const [name, setName] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [scanning, setScanning] = createSignal(false);
  const [cameraFailed, setCameraFailed] = createSignal(false);
  createEffect(() => {
    if (props.open) {
      setGroup(false);
      setCard(props.initial ?? "");
      setName("");
      setCameraFailed(false);
    } else {
      setScanning(false);
    }
  });

  const [lookupFailed, setLookupFailed] = createSignal(false);
  const handle = () => (card().trim().startsWith("@") ? normalize(card()) : undefined);
  const problem = () => {
    const text = card().trim();
    if (!text) return undefined;
    if (handle()) return lookupFailed() ? strings.passkeys.notFound : undefined;
    if (!isContactCard(text)) return strings.notACard;
    if (cardIdentity(text) === props.app.me) return strings.ownCard;
    return undefined;
  };

  const start = async (e: Event) => {
    e.preventDefault();
    if (!card().trim() || problem() || busy()) return;
    setBusy(true);
    try {
      // An @handle is looked up in the directory: it gives a card.
      let target = card().trim();
      if (handle()) {
        const found = await lookup(mailboxBase, target);
        if (!found || cardIdentity(found) === props.app.me) {
          setLookupFailed(true);
          haptic("cancel");
          return;
        }
        target = found;
      }
      const id = await props.app.rt.startConversation(target, name().trim() || (handle() ? `@${handle()}` : undefined));
      haptic("success");
      props.onStarted(id);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={props.open} title={group() ? strings.groups.newGroup : strings.startTitle} onClose={props.onClose}>
      <div class="segmented" role="radiogroup" aria-label={strings.startTitle}>
        <button role="radio" aria-checked={!group()} onClick={() => setGroup(false)}>
          {strings.groups.newChat}
        </button>
        <button
          role="radio"
          aria-checked={group()}
          onClick={() => {
            haptic("toggle");
            setGroup(true);
          }}
        >
          {strings.groups.newGroup}
        </button>
      </div>
      <Show when={group()}>
        <NewGroup app={props.app} onStarted={props.onStarted} />
      </Show>
      <form class="stack" onSubmit={start} hidden={group()}>
        <Show when={scanning()}>
          <Scanner
            onCard={(found) => {
              haptic("success");
              setCard(found);
              setScanning(false);
            }}
            onError={() => {
              setScanning(false);
              setCameraFailed(true);
            }}
          />
        </Show>
        <Show when={canScan() && !scanning()}>
          <button type="button" class="btn ghost" onClick={() => setScanning(true)}>
            <Icon name="scan" size={18} />
            {strings.scan}
          </button>
        </Show>
        <Show when={cameraFailed()}>
          <p class="caption muted">{strings.noCamera}</p>
        </Show>
        <label class="field">
          <span class="label">{strings.cardLabel}</span>
          <textarea
            class="mono-input"
            rows="3"
            placeholder={strings.cardPlaceholder}
            value={card()}
            onInput={(e) => {
              setCard(e.currentTarget.value);
              setLookupFailed(false);
            }}
            autocomplete="off"
            spellcheck={false}
          />
        </label>
        <Show when={problem()}>
          <p class="caption danger" role="alert">
            {problem()}
          </p>
        </Show>
        <label class="field">
          <span class="label">{strings.nameLabel}</span>
          <input
            class="body"
            placeholder={strings.namePlaceholder}
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            maxLength={64}
          />
        </label>
        <button class="btn wide" type="submit" disabled={!card().trim() || !!problem() || busy()}>
          {strings.start}
        </button>
      </form>
    </Sheet>
  );
}

export function MyCardSheet(props: { app: AppState; open: boolean; onClose: () => void }) {
  const [copied, setCopied] = createSignal(false);
  const card = () => props.app.rt.contactCard;
  const link = () => `${webOrigin}/#add=${card()}`;

  const copy = async () => {
    await navigator.clipboard.writeText(card());
    haptic("success");
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };
  const share = async () => {
    haptic("tap");
    if (navigator.share) await navigator.share({ title: "krypt", url: link() }).catch(() => {});
    else await navigator.clipboard.writeText(link());
  };

  return (
    <Sheet open={props.open} title={strings.cardTitle} onClose={props.onClose}>
      <div class="stack">
        <p class="muted body">{strings.cardHint}</p>
        <div class="qr-plate">
          <Qr text={link()} label={strings.cardQr} />
        </div>
        <code class="card-text" tabindex="0">
          {card()}
        </code>
        <p class="meta muted">
          {strings.fingerprint} · {props.app.rt.fingerprint}
        </p>
        <div class="row-actions">
          <button class="btn" onClick={copy}>
            <Icon name="copy" size={18} />
            {copied() ? strings.copied : strings.copy}
          </button>
          <button class="btn ghost" onClick={share}>
            <Icon name="share" size={18} />
            {strings.shareLink}
          </button>
        </div>
      </div>
    </Sheet>
  );
}

/** Opened from an invite link: asks the group's admins to let this
 * device's identity in. */
export function JoinSheet(props: { app: AppState; code: string; open: boolean; onClose: () => void }) {
  const [header] = createResource(() => props.code, (code) => props.app.joinHeader(code));
  const [name, setName] = createSignal(props.app.people[props.app.me]?.name ?? "");
  const [state, setState] = createSignal<"asking" | "sent" | "failed">();
  const ask = async (e: Event) => {
    e.preventDefault();
    const found = header();
    if (!found || state() === "asking") return;
    setState("asking");
    const sent = await props.app.askToJoin(props.code, found.header, name().trim());
    haptic(sent ? "success" : "cancel");
    setState(sent ? "sent" : "failed");
  };
  return (
    <Sheet open={props.open} title={strings.invite.joinTitle} onClose={props.onClose}>
      <Show when={!header.loading} fallback={<p class="body muted">{strings.invite.loading}</p>}>
        <Show when={header()} fallback={<p class="body">{strings.invite.broken}</p>}>
          {(found) => (
            <Show
              when={state() !== "sent"}
              fallback={
                <div class="stack">
                  <p class="body" role="status">
                    {strings.invite.sent}
                  </p>
                  <button class="btn wide" onClick={props.onClose}>
                    {strings.tour.close}
                  </button>
                </div>
              }
            >
              <form class="stack" onSubmit={ask}>
                <p class="headline">{strings.invite.ask(found().name)}</p>
                <p class="caption muted">{strings.invite.askHint}</p>
                <label class="field">
                  <span class="label">{strings.invite.yourName}</span>
                  <input class="body" value={name()} maxLength={64} onInput={(e) => setName(e.currentTarget.value)} />
                </label>
                <Show when={state() === "failed"}>
                  <p class="caption danger" role="alert">
                    {strings.invite.broken}
                  </p>
                </Show>
                <button class="btn wide" type="submit" disabled={state() === "asking"}>
                  {state() === "asking" ? strings.invite.sending : strings.invite.send}
                </button>
              </form>
            </Show>
          )}
        </Show>
      </Show>
    </Sheet>
  );
}

export function InfoSheet(props: { app: AppState; id: string; open: boolean; onClose: () => void; onGone: () => void }) {
  const [checking, setChecking] = createSignal<string>();
  const [deleting, setDeleting] = createSignal(false);
  const [leaving, setLeaving] = createSignal(false);
  const [managing, setManaging] = createSignal<string>();
  const group = () => {
    const c = conversation();
    return !!c && props.app.isGroup(c);
  };
  const [note, setNote] = createSignal<string>();
  const conversation = () => props.app.conversation(props.id);
  const person = (identity: string) => props.app.people[identity] ?? { identity, verified: false };

  const setVerified = async (identity: string, verified: boolean) => {
    await props.app.savePerson({ ...person(identity), verified });
    haptic(verified ? "verify" : "tap");
    setChecking(undefined);
  };
  const rename = async (identity: string, name: string) => {
    await props.app.savePerson({ ...person(identity), name: name.trim() || undefined });
  };
  /** People this device is connected with who are not here yet: a group
   * grows only by people someone in it already knows. */
  const addable = () => {
    const here = new Set(conversation()?.members ?? []);
    return props.app.contacts().filter((c) => !here.has(c.identity));
  };

  return (
    <Sheet open={props.open} title={strings.info} onClose={props.onClose}>
      <div class="stack">
        <Show when={group() && conversation()?.active}>
          <label class="field">
            <span class="label">{strings.groups.rename}</span>
            <input
              class="headline inline-input"
              value={props.app.groupName(props.id)}
              placeholder={strings.groups.namePlaceholder}
              maxLength={64}
              disabled={!props.app.may(props.id, "edit")}
              onChange={(e) => {
                haptic("toggle");
                void props.app.rename(props.id, e.currentTarget.value.trim());
              }}
            />
          </label>
        </Show>
        <h3 class="label">{strings.members}</h3>
        <ul class="list" role="list">
          <For each={conversation()?.members ?? []}>
            {(identity) => (
              <li class="member">
                <Avatar app={props.app} identity={identity} />
                <Show
                  when={identity !== props.app.me}
                  fallback={
                    <span class="list-text">
                      <span class="headline">{strings.you}</span>
                      <span class="meta muted">{fingerprintOf(identity)}</span>
                    </span>
                  }
                >
                  <span class="list-text">
                    <input
                      class="headline inline-input"
                      aria-label={strings.rename}
                      value={person(identity).name ?? ""}
                      placeholder={fingerprintOf(identity).slice(0, 9)}
                      onChange={(e) => void rename(identity, e.currentTarget.value)}
                    />
                    <span class="meta muted">{fingerprintOf(identity)}</span>
                  </span>
                  <button
                    class="chip press"
                    classList={{ ok: person(identity).verified }}
                    onClick={() => {
                      haptic("tap");
                      setChecking(checking() === identity ? undefined : identity);
                    }}
                  >
                    <Icon name={person(identity).verified ? "check" : "shield"} size={14} />
                    {person(identity).verified ? strings.verified : strings.verify}
                  </button>
                  <Show when={group() && props.app.amAdmin(props.id) && conversation()?.active}>
                    <button
                      class="icon-btn"
                      aria-label={strings.admins.manage(props.app.name(identity))}
                      onClick={() => {
                        haptic("tap");
                        setManaging(managing() === identity ? undefined : identity);
                      }}
                    >
                      <Icon name="more" size={18} />
                    </button>
                  </Show>
                </Show>
                <Show when={group() && props.app.admins(props.id).includes(identity)}>
                  <span class="chip admin-chip">{strings.admins.admin}</span>
                </Show>
                <Show when={managing() === identity}>
                  <div class="row-actions member-actions">
                    <button
                      class="btn ghost"
                      onClick={() => {
                        haptic("toggle");
                        const admin = props.app.admins(props.id).includes(identity);
                        setManaging(undefined);
                        void props.app.changeRules(props.id, (p) => ({
                          ...p,
                          admins: admin ? p.admins.filter((a) => a !== identity) : [...p.admins, identity],
                        }));
                      }}
                    >
                      {props.app.admins(props.id).includes(identity) ? strings.admins.removeAdmin : strings.admins.makeAdmin}
                    </button>
                    <button
                      class="btn ghost danger-text"
                      onClick={() => {
                        haptic("hangup");
                        setManaging(undefined);
                        void props.app.removeMember(props.id, identity);
                      }}
                    >
                      {strings.admins.remove}
                    </button>
                  </div>
                </Show>
                <Show when={checking() === identity}>
                  <div class="verify">
                    <p class="label">{strings.safetyNumber}</p>
                    <p class="safety" aria-label={strings.safetyNumber}>
                      {safetyNumber(props.app.me, identity)}
                    </p>
                    <p class="caption muted">{strings.safetyHint}</p>
                    <Show
                      when={person(identity).verified}
                      fallback={
                        <button class="btn" onClick={() => void setVerified(identity, true)}>
                          {strings.markVerified}
                        </button>
                      }
                    >
                      <button class="btn ghost" onClick={() => void setVerified(identity, false)}>
                        {strings.unmarkVerified}
                      </button>
                    </Show>
                  </div>
                </Show>
              </li>
            )}
          </For>
        </ul>
        <Show when={group() && conversation()?.active}>
          <For each={[["add", strings.admins.addTitle], ["edit", strings.admins.editTitle]] as const}>
            {([what, title]) => (
              <>
                <h3 class="label">{title}</h3>
                <div class="segmented" role="radiogroup" aria-label={title}>
                  <For each={[["everyone", strings.admins.everyone], ["admins", strings.admins.onlyAdmins]] as const}>
                    {([who, label]) => (
                      <button
                        role="radio"
                        aria-checked={(props.app.policy(props.id)?.[what] ?? "everyone") === who}
                        disabled={!props.app.amAdmin(props.id)}
                        onClick={() => {
                          haptic("toggle");
                          void props.app.changeRules(props.id, (p) => ({ ...p, [what]: who }));
                        }}
                      >
                        {label}
                      </button>
                    )}
                  </For>
                </div>
              </>
            )}
          </For>
          <Show when={!props.app.amAdmin(props.id)}>
            <p class="caption muted">{strings.admins.adminsOnly}</p>
          </Show>
        </Show>
        <Show when={group() && conversation()?.active}>
          <h3 class="label">{strings.invite.title}</h3>
          <Show
            when={props.app.linkCode(props.id)}
            fallback={
              <Show when={props.app.amAdmin(props.id)}>
                <button
                  class="btn ghost"
                  onClick={() => {
                    haptic("toggle");
                    void props.app.setLink(props.id, true);
                  }}
                >
                  {strings.invite.turnOn}
                </button>
              </Show>
            }
          >
            {(code) => {
              const url = () => `${webOrigin}/#join=${code()}`;
              return (
                <div class="stack">
                  <code class="card-text invite-link" tabindex="0">
                    {url()}
                  </code>
                  <p class="caption muted">{strings.invite.hint}</p>
                  <div class="row-actions">
                    <button
                      class="btn ghost"
                      onClick={() => {
                        void navigator.clipboard?.writeText(url());
                        haptic("success");
                      }}
                    >
                      {strings.invite.copy}
                    </button>
                    <Show when={props.app.amAdmin(props.id)}>
                      <button
                        class="btn ghost"
                        onClick={() => {
                          haptic("toggle");
                          void props.app.setLink(props.id, true);
                        }}
                      >
                        {strings.invite.reset}
                      </button>
                      <button
                        class="btn ghost danger-text"
                        onClick={() => {
                          haptic("toggle");
                          void props.app.setLink(props.id, false);
                        }}
                      >
                        {strings.invite.turnOff}
                      </button>
                    </Show>
                  </div>
                  <Show when={props.app.amAdmin(props.id)}>
                    <p class="caption muted">{strings.invite.resetHint}</p>
                  </Show>
                </div>
              );
            }}
          </Show>
          <Show when={props.app.amAdmin(props.id) && props.app.joinRequests(props.id).length > 0}>
            <h3 class="label">{strings.invite.asks}</h3>
            <ul class="list" role="list" aria-label={strings.invite.asks}>
              <For each={props.app.joinRequests(props.id)}>
                {(request) => (
                  <li class="member join-request">
                    <Avatar app={props.app} identity={request.identity} />
                    <span class="list-text">
                      {/* Someone already known goes by their name here, not the one they typed. */}
                      <span class="headline truncate">
                        {props.app.people[request.identity]
                          ? props.app.name(request.identity)
                          : request.name || fingerprintOf(request.identity).slice(0, 9)}
                      </span>
                      <span class="meta muted">{fingerprintOf(request.identity)}</span>
                    </span>
                    <button
                      class="chip press"
                      onClick={() => {
                        haptic("tap");
                        props.app.declineJoin(props.id, request.id);
                      }}
                    >
                      {strings.invite.decline}
                    </button>
                    <button
                      class="chip press ok"
                      onClick={() => {
                        haptic("success");
                        void props.app.approveJoin(props.id, request.id);
                      }}
                    >
                      {strings.invite.approve}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </Show>
        <Show when={conversation()?.active}>
          <h3 class="label">{strings.timer.title}</h3>
          <div class="segmented wrap" role="radiogroup" aria-label={strings.timer.title}>
            <For each={TIMERS}>
              {(seconds) => (
                <button
                  role="radio"
                  aria-checked={props.app.timer(props.id) === seconds}
                  disabled={!props.app.may(props.id, "edit")}
                  onClick={() => {
                    haptic("toggle");
                    void props.app.setTimer(props.id, seconds);
                  }}
                >
                  {strings.timer.label(seconds)}
                </button>
              )}
            </For>
          </div>
          <p class="caption muted">{strings.timer.hint}</p>
        </Show>
        <h3 class="label">{strings.mute.title}</h3>
        <div class="segmented wrap" role="radiogroup" aria-label={strings.mute.title}>
          <For
            each={
              [
                [strings.mute.on, undefined],
                [strings.mute.hour, 3_600_000],
                [strings.mute.eight, 8 * 3_600_000],
                [strings.mute.week, 7 * 24 * 3_600_000],
                [strings.mute.always, Infinity],
              ] as [string, number | undefined][]
            }
          >
            {([label, length]) => (
              <button
                role="radio"
                aria-checked={
                  length === undefined
                    ? !props.app.isMuted(props.id)
                    : length === Infinity && props.app.mutedUntil(props.id) === Infinity
                }
                onClick={() => {
                  haptic("toggle");
                  void props.app.mute(props.id, length === undefined || length === Infinity ? length : Date.now() + length);
                }}
              >
                {label}
              </button>
            )}
          </For>
        </div>
        <p class="caption muted">
          {props.app.mutedUntil(props.id) === undefined
            ? strings.mute.hint
            : props.app.mutedUntil(props.id) === Infinity
              ? strings.mute.forever
              : strings.mute.until(props.app.mutedUntil(props.id)!)}
        </p>
        <button
          class="btn ghost"
          onClick={() => {
            haptic("toggle");
            const archiving = !props.app.isArchived(props.id);
            void props.app.archive(props.id, archiving).then(() => archiving && props.onGone());
          }}
        >
          {props.app.isArchived(props.id) ? strings.archive.unarchive : strings.archive.archive}
        </button>
        <Show when={conversation()?.active && props.app.may(props.id, "add")}>
          <h3 class="label">{strings.admins.addFromContacts}</h3>
          <Show when={addable().length > 0} fallback={<p class="caption muted">{strings.admins.noOneToAdd}</p>}>
            <ul class="list pick-list" role="list">
              <For each={addable()}>
                {(contact) => (
                  <li class="member">
                    <Avatar app={props.app} identity={contact.identity} />
                    <span class="list-text">
                      <span class="headline truncate">{props.app.name(contact.identity)}</span>
                      <span class="meta muted">{fingerprintOf(contact.identity)}</span>
                    </span>
                    <button
                      class="chip press"
                      onClick={() => {
                        haptic("success");
                        void props.app.rt.invite(props.id, contact.card);
                      }}
                    >
                      {strings.add}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </Show>
        <h3 class="label">{strings.safety.title}</h3>
        <Show when={note()}>{(text) => <p class="caption" role="status">{text()}</p>}</Show>
        <For each={props.app.others(conversation() ?? { id: "", members: [], active: false, epoch: 0 })}>
          {(identity) => (
            <div class="row-actions">
              <button
                class="btn ghost danger-text"
                disabled={props.app.blocked().includes(identity)}
                onClick={() => {
                  haptic("tap");
                  void props.app.block(identity, props.id).then(() => {
                    if (!props.app.conversation(props.id)) props.onGone();
                    else setNote(strings.safety.blocked);
                  });
                }}
              >
                {props.app.blocked().includes(identity) ? strings.safety.blocked : strings.safety.block(props.app.name(identity))}
              </button>
            </div>
          )}
        </For>
        <Show when={group() && conversation()?.active}>
          <Show
            when={leaving()}
            fallback={
              <button class="btn ghost danger-text" onClick={() => setLeaving(true)}>
                {strings.groups.leave}
              </button>
            }
          >
            <div class="verify stack">
              <p class="caption">{strings.groups.leaveHint}</p>
              <div class="row-actions">
                <button class="btn ghost" onClick={() => setLeaving(false)}>
                  {strings.safety.cancel}
                </button>
                <button
                  class="btn danger"
                  onClick={() => {
                    haptic("hangup");
                    void props.app.leaveGroup(props.id).then(props.onGone);
                  }}
                >
                  {strings.groups.leaveConfirm}
                </button>
              </div>
            </div>
          </Show>
        </Show>
        <Show
          when={deleting()}
          fallback={
            <button class="btn ghost danger-text" onClick={() => setDeleting(true)}>
              {strings.safety.delete}
            </button>
          }
        >
          <div class="verify stack">
            <p class="caption">{strings.safety.deleteHint}</p>
            <div class="row-actions">
              <button class="btn ghost" onClick={() => setDeleting(false)}>
                {strings.safety.cancel}
              </button>
              <button
                class="btn danger"
                onClick={() => {
                  haptic("burned");
                  void props.app.deleteChat(props.id).then(props.onGone);
                }}
              >
                {strings.safety.deleteConfirm}
              </button>
            </div>
          </div>
        </Show>
      </div>
    </Sheet>
  );
}
