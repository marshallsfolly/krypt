import { createEffect, createMemo, createSignal, For, on, onCleanup, Show } from "solid-js";
import { haptic } from "../app/appearance";
import { Icon } from "../app/icons";
import type { AppState } from "../app/state";
import { strings } from "../app/strings";
import type { Calls, CallView } from "../runtime/call";
import { Avatar } from "./Avatar";

/** A soft tone pattern while a call rings (`ring`) or is being placed
 * (`back`). Silent where the browser does not allow sound yet. */
function tone(kind: "ring" | "back"): () => void {
  let context: AudioContext;
  try {
    context = new AudioContext();
  } catch {
    return () => {};
  }
  const gain = context.createGain();
  gain.gain.value = 0;
  gain.connect(context.destination);
  const oscillators = (kind === "ring" ? [523.25, 659.25] : [425]).map((frequency) => {
    const oscillator = context.createOscillator();
    oscillator.frequency.value = frequency;
    oscillator.connect(gain);
    oscillator.start();
    return oscillator;
  });
  const [period, length, level] = kind === "ring" ? [3, 1.2, 0.06] : [5, 1, 0.03];
  for (let i = 0; i < 20; i++) {
    const at = context.currentTime + i * period;
    gain.gain.setValueAtTime(0, at);
    gain.gain.linearRampToValueAtTime(level, at + 0.05);
    gain.gain.setValueAtTime(level, at + length - 0.05);
    gain.gain.linearRampToValueAtTime(0, at + length);
  }
  return () => {
    for (const oscillator of oscillators) oscillator.stop();
    void context.close();
  };
}

/** A media element showing a stream. Setting `srcObject` restarts the
 * element (a black frame), even to the same stream, so only a new stream is
 * set; the call view is republished every few seconds with the same ones. */
function Stream(props: { stream?: MediaStream; muted?: boolean; class: string; label: string }) {
  let video!: HTMLVideoElement;
  const stream = createMemo(() => props.stream);
  createEffect(() => {
    const current = stream();
    video.srcObject = current ?? null;
    if (current) void video.play().catch(() => {});
  });
  return <video ref={video} class={props.class} autoplay playsinline muted={props.muted} aria-label={props.label} />;
}

function status(app: AppState, view: CallView, now: number): string {
  switch (view.state) {
    case "outgoing":
      return view.group ? strings.calls.waitingForOthers : strings.calls.calling;
    case "incoming":
      if (view.group) return strings.calls.groupRings(app.name(view.peer), view.video);
      return view.video ? strings.calls.incomingVideo : strings.calls.incomingVoice;
    case "connecting":
      return strings.calls.connecting;
    case "reconnecting":
      return strings.calls.reconnecting;
    case "connected": {
      const time = strings.calls.duration(Math.max(0, Math.round((now - (view.connectedAt ?? now)) / 1000)));
      return view.group ? `${time} · ${strings.calls.people(view.peers.length)}` : time;
    }
    case "ended":
      return strings.calls.ended[view.outcome ?? "completed"];
  }
}

/** The call screen: ringing, placing, and in a call. The encryption state and
 * the media path stay visible the whole time, in every theme. */
export function CallScreen(props: { app: AppState; calls: Calls }) {
  const [now, setNow] = createSignal(Date.now());
  const clock = setInterval(() => setNow(Date.now()), 1000);
  onCleanup(() => clearInterval(clock));

  // Sound and haptics follow the call's state.
  let ringing: ReturnType<typeof setInterval> | undefined;
  let stopTone = () => {};
  const quiet = () => {
    clearInterval(ringing);
    ringing = undefined;
    stopTone();
    stopTone = () => {};
  };
  onCleanup(quiet);
  createEffect(
    on(
      () => props.calls.current()?.state,
      (state, previous) => {
        quiet();
        if (state === "incoming") {
          haptic("ring");
          ringing = setInterval(() => haptic("ring"), 2_000);
          stopTone = tone("ring");
        } else if (state === "outgoing") {
          stopTone = tone("back");
        } else if (state === "connected" && previous !== "reconnecting") {
          haptic("success");
        } else if (state === "ended") {
          haptic("hangup");
        }
      },
    ),
  );

  const press = (work: () => unknown) => () => {
    haptic("toggle");
    void work();
  };

  return (
    <Show when={props.calls.current()}>
      {(view) => {
        const first = () => view().peers[0];
        // The worst path shown: relayed if any connection is.
        const pathOf = () =>
          view().peers.some((p) => p.path === "relayed") ? "relayed" : view().peers.some((p) => p.path) ? "direct" : undefined;
        const rtt = () => (view().group ? undefined : first()?.rttMs);
        const path = () => strings.calls.path(pathOf(), rtt());
        const title = () => {
          if (!view().group) return props.app.name(view().peer);
          const c = props.app.conversation(view().conversation);
          return c ? props.app.title(c) : props.app.name(view().peer);
        };
        const tiles = () => view().peers.filter((p) => p.device || !view().group);
        // Tiles are kept by device, so a republished view (new objects, same
        // people) keeps each video element playing.
        const devices = createMemo(() => tiles().map((p) => p.device), undefined, {
          equals: (a, b) => a.length === b.length && a.every((d, i) => d === b[i]),
        });
        return (
          <div
            class="call"
            classList={{ "call-group": view().group && tiles().length > 1 }}
            role="dialog"
            aria-modal="true"
            aria-label={title()}
            data-call-state={view().state}
            data-call-path={pathOf() ?? ""}
            data-peers={tiles().length}
          >
            <div class="call-tiles">
              <Show
                when={tiles().length > 0}
                fallback={
                  <div class="call-person">
                    <Avatar app={props.app} identity={view().peer} />
                  </div>
                }
              >
                <For each={devices()}>
                  {(device) => {
                    const peer = createMemo(() => tiles().find((p) => p.device === device));
                    const identity = () => peer()?.identity ?? "";
                    return (
                      <div class="call-tile" data-device={device}>
                        <Stream class="call-remote" stream={peer()?.remote} label={props.app.name(identity())} />
                        <Show when={!(peer()?.remoteCamera && peer()!.remote.getVideoTracks().length > 0)}>
                          <div class="call-person">
                            <Avatar app={props.app} identity={identity()} />
                          </div>
                        </Show>
                        <Show when={view().group}>
                          <span class="call-name label">{props.app.name(identity())}</span>
                        </Show>
                      </div>
                    );
                  }}
                </For>
              </Show>
            </div>
            <header class="call-head">
              <h1 class="title">{title()}</h1>
              <p class="call-status body">{status(props.app, view(), now())}</p>
              <p class="label status ok call-secure">
                <Icon name="shield" size={13} />
                {strings.calls.encrypted}
                <Show when={path()}>
                  <span class="call-path"> · {path()}</span>
                </Show>
              </p>
            </header>
            <Show when={view().camera && view().local && view().state !== "incoming"}>
              <Stream class="call-local" stream={view().local} muted label={strings.you} />
            </Show>
            <footer class="call-controls">
              <Show
                when={view().state === "incoming"}
                fallback={
                  <Show when={view().state !== "ended"}>
                    <button
                      class="call-btn press"
                      aria-pressed={view().muted}
                      aria-label={view().muted ? strings.calls.unmute : strings.calls.mute}
                      onClick={press(() => props.calls.toggleMute())}
                    >
                      <Icon name={view().muted ? "micOff" : "mic"} size={26} />
                    </button>
                    <button
                      class="call-btn press"
                      aria-pressed={!view().camera}
                      aria-label={view().camera ? strings.calls.cameraOff : strings.calls.cameraOn}
                      disabled={view().state === "outgoing" && !view().local}
                      onClick={press(() => props.calls.toggleCamera())}
                    >
                      <Icon name={view().camera ? "video" : "videoOff"} size={26} />
                    </button>
                    <Show when={view().camera && (view().cameras ?? 0) > 1}>
                      <button class="call-btn press" aria-label={strings.calls.flip} onClick={press(() => props.calls.flipCamera())}>
                        <Icon name="flip" size={26} />
                      </button>
                    </Show>
                    <button
                      class="call-btn end press"
                      aria-label={strings.calls.hangup}
                      onClick={() => {
                        haptic("hangup");
                        void props.calls.hangup();
                      }}
                    >
                      <Icon name="hangup" size={28} />
                    </button>
                  </Show>
                }
              >
                <button
                  class="call-btn end press"
                  aria-label={strings.calls.decline}
                  onClick={() => {
                    haptic("hangup");
                    void props.calls.decline();
                  }}
                >
                  <Icon name="hangup" size={28} />
                </button>
                <button
                  class="call-btn accept press"
                  aria-label={view().group ? strings.calls.join : strings.calls.accept}
                  onClick={() => {
                    haptic("tap");
                    void props.calls.accept();
                  }}
                >
                  <Icon name={view().video ? "video" : "phone"} size={28} />
                </button>
              </Show>
            </footer>
          </div>
        );
      }}
    </Show>
  );
}
