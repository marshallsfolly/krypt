// Calls: WebRTC between devices, set up through the conversation itself.
// Offers, answers and ICE candidates travel as MLS messages, so the DTLS
// fingerprints inside them (which key the media's encryption) are
// authenticated end to end: the mailbox, Cloudflare's relay and the network
// only ever carry encrypted media. One call at a time.
//
// One-to-one: the ring is an offer to every device of the other person; the
// first to answer gets the call and the others stop. Nothing about the
// callee (not even its network addresses) reaches the caller until it
// answers. A second caller hears "busy".
//
// Groups: a mesh, every participant connected to every other. Joining is a
// `join` to everyone (the first one rings the group); for each pair, the
// device with the lower id sends the offer, so two never offer at once. A
// participant leaves with an `end`. Each device's video is shared out among
// its connections, so a mesh stays within one phone's upload.

import { createSignal } from "solid-js";
import type { CallSignal } from "../core/krypt_wasm.js";
import type { Runtime } from "./device";
import type { CallRecord } from "./store";

/** Addressed to every device of the other members. */
const EVERYONE = "0".repeat(64);
/** An unanswered call gives up after this long. */
const RING_MS = 45_000;
/** A ring older than this when it arrives (the device was offline) is a
 * missed call, not a ring. */
const STALE_MS = 60_000;
/** How long to collect ICE candidates before sending a description; later
 * ones follow in a batch. */
const GATHER_MS = 1_500;
const CANDIDATE_BATCH_MS = 250;
/** A lost connection gets this long to come back before it is dropped. */
const RECONNECT_MS = 12_000;
const STATS_MS = 2_000;
/** Relay credentials are renewed this long before they expire. */
const REFRESH_MARGIN_S = 600;
/** Most devices in a group call: a mesh sends each device's media to all
 * the others, which past this many is more than a phone can upload. */
export const GROUP_CALL_MAX = 8;
/** Video this device sends, in all, shared among its connections. */
const UPLINK_BPS = 2_500_000;
const VIDEO_MIN_BPS = 200_000;
/** Call ids remembered, so a call rings once. */
const SEEN_MAX = 256;

export type CallState = "outgoing" | "incoming" | "connecting" | "connected" | "reconnecting" | "ended";

/** One other device in the call. */
export interface PeerView {
  device: string;
  identity: string;
  state: "connecting" | "connected" | "reconnecting";
  remote: MediaStream;
  /** Its camera is sending. */
  remoteCamera: boolean;
  path?: "direct" | "relayed";
  rttMs?: number;
}

export interface CallView {
  id: string;
  conversation: string;
  group: boolean;
  /** One-to-one: the other person. Group: who rang (identity, hex). */
  peer: string;
  direction: "out" | "in";
  video: boolean;
  state: CallState;
  connectedAt?: number;
  muted: boolean;
  camera: boolean;
  /** Cameras this device has (whether flipping makes sense). */
  cameras?: number;
  local?: MediaStream;
  /** The devices this one is connected (or connecting) to. */
  peers: PeerView[];
  /** Group: everyone else in the call, by identity (connected or not). */
  members: string[];
  outcome?: CallRecord["outcome"];
}

/** A group call running in a conversation, as this device knows it. */
export interface ActiveCall {
  id: string;
  video: boolean;
  /** Devices in it, with their identities. */
  members: Map<string, string>;
}

interface Peer extends PeerView {
  pc: RTCPeerConnection;
  /** Sends the offers (and so restarts ICE); the other side answers. */
  offerer: boolean;
  described: boolean;
  outbox: string[];
  early: string[];
  lost?: ReturnType<typeof setTimeout>;
}

interface Call {
  id: string;
  conversation: string;
  group: boolean;
  direction: "out" | "in";
  video: boolean;
  state: CallState;
  peer: string;
  connectedAt?: number;
  muted: boolean;
  camera: boolean;
  cameras?: number;
  local?: MediaStream;
  servers?: RTCIceServer[];
  /** By device; a one-to-one caller's peer is "" until someone answers. */
  peers: Map<string, Peer>;
  /** Group: other devices in the call, with their identities. */
  members: Map<string, string>;
  /** Group: this device has joined (not only ringing). */
  joined: boolean;
  /** Group: settles once the microphone (and camera) are ready. Offers made
   * or answered before then would carry none of this device's media. */
  prepared?: Promise<void>;
  /** Group: candidates from devices whose offer is waiting for `prepared`. */
  early?: Map<string, string[]>;
  /** One-to-one, ringing: the caller's offer. */
  offer?: { sdp: string; device: string; candidates: string[] };
  outcome?: CallRecord["outcome"];
}

const randomId = () => [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");

function waitForCandidates(pc: RTCPeerConnection): Promise<void> {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === "complete") return resolve();
    const timer = setTimeout(resolve, GATHER_MS);
    pc.addEventListener("icegatheringstatechange", () => {
      if (pc.iceGatheringState === "complete") {
        clearTimeout(timer);
        resolve();
      }
    });
  });
}

const VIDEO: MediaTrackConstraints = { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } };

const relays = (server: RTCIceServer) =>
  (Array.isArray(server.urls) ? server.urls : [server.urls]).some((url) => url.startsWith("turn"));

export class Calls {
  private readonly state = createSignal<CallView>();
  /** The call on screen, if any. */
  readonly current = this.state[0];
  private readonly setView = this.state[1];
  private call?: Call;
  private timers: ReturnType<typeof setTimeout>[] = [];
  private stats?: ReturnType<typeof setInterval>;
  /** Group calls running in each conversation. */
  private active = new Map<string, ActiveCall>();
  private readonly activeVersion = createSignal(0);
  private seen = new Set<string>();
  /** Missed calls found while catching up, recorded once their step is
   * fully read (a later signal may say they were answered elsewhere). */
  private missed = new Map<string, { conversation: string; video: boolean; group: boolean; outcome: CallRecord["outcome"] }>();

  constructor(
    private rt: Runtime,
    /** "Always relay calls": hides this device's address from the others. */
    private relayOnly: () => boolean,
    private onRing: (view: CallView) => void,
  ) {
    rt.onCall((conversation, from, device, sentAtMs, signal) =>
      void this.receive(conversation, from, device, sentAtMs, signal).catch((error) => {
        console.error("call signal", error);
        void this.end("failed", true);
      }),
    );
  }

  /** The group call running in a conversation, which this device can join. */
  activeIn(conversation: string): ActiveCall | undefined {
    this.activeVersion[0]();
    const call = this.active.get(conversation);
    return call && call.members.size > 0 ? call : undefined;
  }

  private touchActive() {
    this.activeVersion[1]((v) => v + 1);
  }

  /** Shows the call as it now stands. */
  private emit() {
    const c = this.call;
    if (!c) return this.setView(undefined);
    this.setView({
      id: c.id,
      conversation: c.conversation,
      group: c.group,
      peer: c.peer,
      direction: c.direction,
      video: c.video,
      state: c.state,
      connectedAt: c.connectedAt,
      muted: c.muted,
      camera: c.camera,
      cameras: c.cameras,
      local: c.local,
      peers: [...c.peers.values()].map(({ device, identity, state, remote, remoteCamera, path, rttMs }) => ({
        device,
        identity,
        state,
        remote,
        remoteCamera,
        path,
        rttMs,
      })),
      members: [...new Set(c.members.values())],
      outcome: c.outcome,
    });
  }

  private send(signal: Omit<CallSignal, "call" | "video" | "sdp"> & Partial<Pick<CallSignal, "video" | "sdp">>) {
    const c = this.call;
    if (!c) return;
    void this.rt.sendCall(c.conversation, { video: false, sdp: "", ...signal, call: c.id } as CallSignal);
  }

  // ---- Starting, answering and ending -----------------------------------

  /** Calls a conversation: `others` are its other members. In a group with a
   * call already running, joins it. */
  async start(conversation: string, others: string[], video: boolean): Promise<void> {
    if (this.call) return;
    const group = others.length > 1;
    const running = group ? this.activeIn(conversation) : undefined;
    if (running) return this.joinRunning(conversation, running, video);
    const id = randomId();
    this.call = {
      id,
      conversation,
      group,
      direction: "out",
      video,
      state: "outgoing",
      peer: group ? "" : (others[0] ?? ""),
      muted: false,
      camera: video,
      peers: new Map(),
      members: new Map(),
      joined: group,
    };
    this.seen.add(id);
    this.emit();
    try {
      const prepared = this.prepare(video);
      // Failing ends the call, which those waiting check for.
      if (group) this.call.prepared = prepared.catch(() => {});
      await prepared;
      if (this.call?.id !== id) return;
      if (group) {
        this.send({ to: EVERYONE, kind: "join", video });
        // Members who joined while the camera was starting.
        for (const [device, identity] of this.call.members) void this.offerTo(device, identity);
      } else {
        const peer = this.connect("", others[0] ?? "", true);
        await peer.pc.setLocalDescription(await peer.pc.createOffer());
        await waitForCandidates(peer.pc);
        if (this.call?.id !== id) return;
        peer.described = true;
        this.send({ to: EVERYONE, kind: "offer", video, sdp: peer.pc.localDescription!.sdp });
      }
      this.later(RING_MS, () => {
        const c = this.call;
        if (c?.id === id && c.state === "outgoing" && c.members.size === 0) {
          this.send({ to: EVERYONE, kind: "end", reason: group ? "hangup" : "unanswered" });
          void this.end("unanswered");
        }
      });
    } catch (error) {
      console.error("starting a call", error);
      await this.end("failed", true);
      if (error instanceof RelayUnavailable) throw error;
    }
  }

  /** Joins a group call already running. */
  private async joinRunning(conversation: string, running: ActiveCall, video: boolean) {
    if (running.members.size >= GROUP_CALL_MAX - 1) throw new CallFull();
    this.call = {
      id: running.id,
      conversation,
      group: true,
      direction: "in",
      video,
      state: "connecting",
      peer: [...running.members.values()][0] ?? "",
      muted: false,
      camera: video,
      peers: new Map(),
      members: new Map(running.members),
      joined: false,
    };
    this.seen.add(running.id);
    this.emit();
    await this.join();
  }

  /** This device joins the group call it rings for (or was asked into). */
  private async join() {
    const c = this.call;
    if (!c?.group) return;
    c.joined = true;
    c.state = "connecting";
    this.emit();
    try {
      const prepared = this.prepare(c.camera);
      c.prepared = prepared.catch(() => {});
      await prepared;
      if (this.call !== c) return;
      this.send({ to: EVERYONE, kind: "join", video: c.video });
      for (const [device, identity] of c.members) void this.offerTo(device, identity);
    } catch (error) {
      console.error("joining a call", error);
      await this.end("failed", true);
    }
  }

  async accept(): Promise<void> {
    const c = this.call;
    if (!c || c.state !== "incoming") return;
    this.clearTimers();
    if (c.group) {
      if (c.members.size >= GROUP_CALL_MAX) return this.end("failed");
      return this.join();
    }
    const offer = c.offer;
    if (!offer) return;
    c.offer = undefined;
    c.state = "connecting";
    this.emit();
    try {
      await this.prepare(c.video);
      if (this.call !== c) return;
      const peer = this.connect(offer.device, c.peer, false);
      await this.answer(peer, offer.sdp);
      for (const line of offer.candidates) await this.addCandidate(peer, line);
      this.flushCandidates(peer);
    } catch (error) {
      console.error("answering a call", error);
      await this.end("failed", true);
    }
  }

  async decline(): Promise<void> {
    if (this.call?.state !== "incoming") return;
    // In a group this only tells this identity's other devices to stop.
    this.send({ to: EVERYONE, kind: "end", reason: "declined" });
    await this.end("declined");
  }

  async hangup(): Promise<void> {
    const c = this.call;
    if (!c || c.state === "ended") return;
    if (c.state === "incoming") return this.decline();
    this.send({ to: EVERYONE, kind: "end", reason: "hangup" });
    await this.end(c.connectedAt ? "completed" : c.direction === "out" ? "unanswered" : "completed");
  }

  toggleMute() {
    const c = this.call;
    if (!c?.local) return;
    c.muted = !c.muted;
    for (const track of c.local.getAudioTracks()) track.enabled = !c.muted;
    this.emit();
  }

  /** Turns the camera on or off. Off stops it (the light goes out); video
   * stays negotiated, so turning it back on needs no renegotiation. */
  async toggleCamera(): Promise<void> {
    const c = this.call;
    if (!c?.local) return;
    if (c.camera) {
      for (const track of c.local.getVideoTracks()) {
        track.stop();
        c.local.removeTrack(track);
      }
      for (const peer of c.peers.values()) await this.videoSender(peer)?.replaceTrack(null);
      c.camera = false;
      c.local = new MediaStream(c.local.getTracks());
      return this.emit();
    }
    const stream = await navigator.mediaDevices.getUserMedia({ video: VIDEO });
    const [track] = stream.getVideoTracks();
    if (!track || this.call !== c) return stream.getTracks().forEach((t) => t.stop());
    for (const peer of c.peers.values()) await this.videoSender(peer)?.replaceTrack(track);
    c.local.addTrack(track);
    c.camera = true;
    c.local = new MediaStream(c.local.getTracks());
    this.emit();
  }

  /** Switches between the front and back cameras, where there are two. */
  async flipCamera(): Promise<void> {
    const c = this.call;
    const current = c?.local?.getVideoTracks()[0];
    if (!c?.local || !current) return;
    const facing = current.getSettings().facingMode === "environment" ? "user" : "environment";
    const stream = await navigator.mediaDevices.getUserMedia({ video: { ...VIDEO, facingMode: { exact: facing } } });
    const [track] = stream.getVideoTracks();
    if (!track) return;
    for (const peer of c.peers.values()) await this.videoSender(peer)?.replaceTrack(track);
    current.stop();
    c.local.removeTrack(current);
    c.local.addTrack(track);
    c.local = new MediaStream(c.local.getTracks());
    this.emit();
  }

  // ---- Signals from the conversation ------------------------------------

  private async receive(conversation: string, from: string, device: string, sentAtMs: number, signal: CallSignal) {
    const me = this.rt.identity;
    const mine = this.rt.deviceId;
    if (signal.kind === "join") return this.onJoin(conversation, from, device, sentAtMs, signal);
    if (signal.kind === "end" && signal.to === EVERYONE) this.leftActive(conversation, signal.call, device);
    const c = this.call?.id === signal.call ? this.call : undefined;
    if (signal.to !== EVERYONE && signal.to !== mine) {
      // For another device. Only one thing matters here: one of my other
      // devices answering a call that rings here.
      if (from === me && signal.kind === "answer") {
        if (c?.state === "incoming") await this.end("elsewhere");
        const missed = this.missed.get(signal.call);
        if (missed) missed.outcome = "elsewhere";
      }
      return;
    }
    switch (signal.kind) {
      case "offer": {
        if (from === me) return; // My other device is calling.
        if (c) {
          // A group connection, or a restart on an existing one.
          if (!c.peers.has(device) && !(c.group && c.joined)) return;
          // Connected and answered once this device's media and relays are
          // ready, so the connection is made with them (never without the
          // relay it must use) and the answer carries the media;
          // candidates arriving meanwhile wait in `early`.
          await c.prepared;
          if (this.call !== c) return;
          const peer = c.peers.get(device) ?? this.connect(device, from, false);
          await this.answer(peer, signal.sdp);
          return;
        }
        // Someone this device does not know (a message request) cannot make
        // it ring; the call shows as missed in the request.
        if (Date.now() - sentAtMs > STALE_MS || this.rt.isRequest(conversation)) {
          this.miss(signal.call, conversation, signal.video, false);
          return;
        }
        const busy = this.call;
        if (busy && busy.state !== "ended") {
          // Both called each other at once: the lower call id wins, on both
          // sides, and the other call quietly gives way to it.
          const glare = !busy.group && busy.direction === "out" && busy.state === "outgoing" && busy.conversation === conversation;
          if (glare && signal.call < busy.id) {
            this.send({ to: EVERYONE, kind: "end", reason: "hangup" });
            this.close();
            this.ringOne(conversation, from, device, signal);
            return this.accept();
          }
          if (!glare) void this.rt.sendCall(conversation, { call: signal.call, to: device, kind: "end", reason: "busy", video: false, sdp: "" });
          return;
        }
        this.ringOne(conversation, from, device, signal);
        return;
      }
      case "answer": {
        if (!c) return;
        let peer = c.peers.get(device);
        if (!peer && !c.group) {
          const waiting = c.peers.get("");
          if (!waiting) {
            // Another of their devices answered too late.
            void this.rt.sendCall(conversation, { call: signal.call, to: device, kind: "end", reason: "hangup", video: false, sdp: "" });
            return;
          }
          c.peers.delete("");
          waiting.device = device;
          c.peers.set(device, waiting);
          peer = waiting;
          this.clearTimers();
          if (c.state === "outgoing") c.state = "connecting";
          this.emit();
        }
        if (!peer || peer.pc.signalingState !== "have-local-offer") return;
        await peer.pc.setRemoteDescription({ type: "answer", sdp: signal.sdp });
        for (const line of peer.early.splice(0)) await this.addCandidate(peer, line);
        this.flushCandidates(peer);
        return;
      }
      case "candidates": {
        if (from === me || !c) return;
        const lines = signal.sdp.split("\n").filter((l) => l.length > 0);
        if (c.offer) {
          c.offer.candidates.push(...lines);
          return;
        }
        const peer = c.peers.get(device) ?? (!c.group ? c.peers.get("") : undefined);
        if (!peer) {
          if (c.group && c.joined) {
            c.early ??= new Map();
            c.early.set(device, [...(c.early.get(device) ?? []), ...lines].slice(-64));
          }
          return;
        }
        if (peer.pc.remoteDescription) for (const line of lines) await this.addCandidate(peer, line);
        else peer.early.push(...lines);
        return;
      }
      case "end": {
        const missed = this.missed.get(signal.call);
        if (missed && from === me && signal.reason === "declined") missed.outcome = "declined";
        if (!c) return;
        if (c.group) return this.endInGroup(c, from, device, signal);
        if (from === me) {
          // My other device declined the call ringing here.
          if (c.state === "incoming") await this.end(signal.reason === "declined" ? "declined" : "elsewhere");
          return;
        }
        const peer = [...c.peers.values()][0];
        if (peer?.device && device !== peer.device) return;
        const outcome: CallRecord["outcome"] = c.connectedAt
          ? "completed"
          : signal.reason === "declined"
            ? "declined"
            : signal.reason === "busy"
              ? "busy"
              : signal.reason === "failed"
                ? "failed"
                : c.direction === "in"
                  ? "missed"
                  : "unanswered";
        await this.end(outcome);
        return;
      }
    }
  }

  /** A device is in a group call. */
  private onJoin(conversation: string, from: string, device: string, sentAtMs: number, signal: CallSignal) {
    const me = this.rt.identity;
    const running = this.active.get(conversation);
    if (running?.id === signal.call) running.members.set(device, from);
    else this.active.set(conversation, { id: signal.call, video: signal.video, members: new Map([[device, from]]) });
    this.touchActive();
    const c = this.call?.id === signal.call ? this.call : undefined;
    if (from === me) {
      // My other device joined: it took the call.
      if (c?.state === "incoming") void this.end("elsewhere");
      const missed = this.missed.get(signal.call);
      if (missed) missed.outcome = "elsewhere";
      return;
    }
    if (c) {
      c.members.set(device, from);
      if (c.joined) {
        this.clearTimers();
        if (c.state === "outgoing") c.state = "connecting";
        void this.offerTo(device, from);
      }
      this.emit();
      return;
    }
    if (this.seen.has(signal.call)) return;
    this.remember(signal.call);
    if (Date.now() - sentAtMs > STALE_MS || this.rt.isRequest(conversation)) {
      this.miss(signal.call, conversation, signal.video, true);
      return;
    }
    if (this.call) return; // Busy: the call stays joinable from the chat.
    this.call = {
      id: signal.call,
      conversation,
      group: true,
      direction: "in",
      video: signal.video,
      state: "incoming",
      peer: from,
      muted: false,
      camera: signal.video,
      peers: new Map(),
      members: new Map([[device, from]]),
      joined: false,
    };
    // Asking for relay credentials now saves time when joining.
    void this.rt.iceServers(conversation).catch(() => {});
    this.later(RING_MS, () => {
      if (this.call?.id === signal.call && this.call.state === "incoming") void this.end("missed");
    });
    this.emit();
    this.onRing(this.current()!);
  }

  /** Someone left a group call (or, from this identity, declined it). */
  private async endInGroup(c: Call, from: string, device: string, signal: CallSignal) {
    if (from === this.rt.identity) {
      if (c.state === "incoming") await this.end(signal.reason === "declined" ? "declined" : "elsewhere");
      return;
    }
    if (signal.reason === "declined" || !c.members.has(device)) return;
    c.members.delete(device);
    this.drop(c, device);
    if (c.members.size === 0) {
      // Everyone else left.
      if (c.state === "incoming") return this.end("missed");
      if (c.joined) return this.end(c.connectedAt ? "completed" : "unanswered");
    }
    this.emit();
  }

  private leftActive(conversation: string, call: string, device: string) {
    const running = this.active.get(conversation);
    if (running?.id !== call) return;
    running.members.delete(device);
    if (running.members.size === 0) this.active.delete(conversation);
    this.touchActive();
  }

  private ringOne(conversation: string, from: string, device: string, signal: CallSignal) {
    this.remember(signal.call);
    this.call = {
      id: signal.call,
      conversation,
      group: false,
      direction: "in",
      video: signal.video,
      state: "incoming",
      peer: from,
      muted: false,
      camera: signal.video,
      peers: new Map(),
      members: new Map(),
      joined: false,
      offer: { sdp: signal.sdp, device, candidates: [] },
    };
    void this.rt.iceServers(conversation).catch(() => {});
    this.later(RING_MS, () => {
      if (this.call?.id === signal.call && this.call.state === "incoming") void this.end("missed");
    });
    this.emit();
    this.onRing(this.current()!);
  }

  private remember(id: string) {
    if (this.seen.size >= SEEN_MAX) this.seen.clear();
    this.seen.add(id);
  }

  private miss(id: string, conversation: string, video: boolean, group: boolean) {
    if (this.missed.has(id)) return;
    this.missed.set(id, { conversation, video, group, outcome: "missed" });
    queueMicrotask(() => this.recordMissed());
  }

  private recordMissed() {
    for (const [id, missed] of this.missed) {
      this.missed.delete(id);
      void this.rt.recordCall(missed.conversation, {
        direction: "in",
        video: missed.video,
        group: missed.group,
        outcome: missed.outcome,
        seconds: 0,
      });
    }
  }

  // ---- Connections ------------------------------------------------------

  /** Camera and microphone, and relay credentials, for the call. */
  private async prepare(video: boolean) {
    const c = this.call!;
    const [servers, local] = await Promise.all([
      this.rt.iceServers(c.conversation),
      navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: video ? VIDEO : false,
      }),
    ]);
    if (this.call !== c) {
      local.getTracks().forEach((t) => t.stop());
      return;
    }
    // Relaying is a promise to the user: without a relay, no call at all,
    // rather than a direct one that shows the other side their address.
    if (this.relayOnly() && !servers.some(relays)) {
      local.getTracks().forEach((t) => t.stop());
      throw new RelayUnavailable();
    }
    // Device labels and counts are only known once access is granted.
    const devices = await navigator.mediaDevices.enumerateDevices();
    c.servers = servers;
    c.local = local;
    c.cameras = devices.filter((d) => d.kind === "videoinput").length;
    this.scheduleRefresh();
    this.emit();
  }

  /** A connection to `device`. The offerer adds its media now; the other
   * side after reading the offer (`answer`). Both always negotiate video, so
   * the camera can be turned on mid-call. */
  private connect(device: string, identity: string, offerer: boolean): Peer {
    const c = this.call!;
    const servers = c.servers ?? [];
    const pc = new RTCPeerConnection({
      iceServers: servers,
      iceTransportPolicy: this.relayOnly() ? "relay" : "all",
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
    });
    const peer: Peer = {
      device,
      identity,
      pc,
      remote: new MediaStream(),
      remoteCamera: false,
      state: "connecting",
      offerer,
      described: false,
      outbox: [],
      // Candidates that came while this device was getting ready.
      early: c.early?.get(device) ?? [],
    };
    c.early?.delete(device);
    c.peers.set(device, peer);
    pc.ontrack = (event) => {
      peer.remote.addTrack(event.track);
      if (event.track.kind === "video") {
        peer.remoteCamera = !event.track.muted;
        event.track.onmute = () => {
          peer.remoteCamera = false;
          this.emit();
        };
        event.track.onunmute = () => {
          peer.remoteCamera = true;
          this.emit();
        };
      }
      peer.remote = new MediaStream(peer.remote.getTracks());
      this.emit();
    };
    pc.onicecandidate = (event) => {
      if (!event.candidate || !peer.described) return;
      peer.outbox.push(event.candidate.candidate);
      if (peer.outbox.length === 1) this.later(CANDIDATE_BATCH_MS, () => this.flushCandidates(peer));
    };
    pc.onconnectionstatechange = () => this.onConnection(peer);
    if (offerer && c.local) {
      for (const track of c.local.getAudioTracks()) pc.addTrack(track, c.local);
      const [camera] = c.local.getVideoTracks();
      if (camera) pc.addTrack(camera, c.local);
      else pc.addTransceiver("video", { direction: "sendrecv" });
    }
    this.shareUplink();
    this.emit();
    return peer;
  }

  /** In a group, offers to a member when this device's id is the lower. */
  private async offerTo(device: string, identity: string) {
    const c = this.call;
    if (!c?.joined || c.peers.has(device) || !(this.rt.deviceId < device)) return;
    await c.prepared;
    if (this.call !== c || c.peers.has(device)) return;
    const peer = this.connect(device, identity, true);
    await peer.pc.setLocalDescription(await peer.pc.createOffer());
    await waitForCandidates(peer.pc);
    if (this.call !== c || c.peers.get(device) !== peer) return;
    peer.described = true;
    this.send({ to: device, kind: "offer", video: c.video, sdp: peer.pc.localDescription!.sdp });
    this.flushCandidates(peer);
  }

  /** Answers an offer (a new connection, or a restart of one). */
  private async answer(peer: Peer, sdp: string) {
    const c = this.call!;
    peer.described = false;
    await peer.pc.setRemoteDescription({ type: "offer", sdp });
    if (c.local && peer.pc.getSenders().every((s) => !s.track)) {
      for (const track of c.local.getTracks()) peer.pc.addTrack(track, c.local);
      for (const transceiver of peer.pc.getTransceivers()) {
        if (transceiver.receiver.track.kind === "video") transceiver.direction = "sendrecv";
      }
      this.shareUplink();
    }
    await peer.pc.setLocalDescription(await peer.pc.createAnswer());
    for (const line of peer.early.splice(0)) await this.addCandidate(peer, line);
    await waitForCandidates(peer.pc);
    if (this.call !== c) return;
    peer.described = true;
    this.send({ to: peer.device, kind: "answer", video: c.video, sdp: peer.pc.localDescription!.sdp });
    this.flushCandidates(peer);
  }

  private videoSender(peer: Peer): RTCRtpSender | undefined {
    return peer.pc.getTransceivers().find((t) => t.receiver.track.kind === "video")?.sender;
  }

  /** Shares this device's video upload among its connections. */
  private shareUplink() {
    const c = this.call;
    if (!c) return;
    const each = Math.max(VIDEO_MIN_BPS, Math.floor(UPLINK_BPS / Math.max(1, c.peers.size)));
    for (const peer of c.peers.values()) {
      const sender = this.videoSender(peer);
      const parameters = sender?.getParameters();
      if (!sender || !parameters?.encodings?.length) continue;
      parameters.encodings[0]!.maxBitrate = each;
      void sender.setParameters(parameters).catch(() => {});
    }
  }

  private flushCandidates(peer: Peer) {
    if (peer.outbox.length === 0 || !peer.described) return;
    const lines = peer.outbox.splice(0);
    this.send({ to: peer.device || EVERYONE, kind: "candidates", sdp: lines.join("\n") });
  }

  private async addCandidate(peer: Peer, line: string) {
    try {
      await peer.pc.addIceCandidate({ candidate: line, sdpMid: "0", sdpMLineIndex: 0 });
    } catch {
      // A candidate this browser cannot use; the others carry the call.
    }
  }

  private onConnection(peer: Peer) {
    const c = this.call;
    if (!c || c.peers.get(peer.device) !== peer) return;
    switch (peer.pc.connectionState) {
      case "connected":
        clearTimeout(peer.lost);
        peer.lost = undefined;
        peer.state = "connected";
        c.state = "connected";
        c.connectedAt ??= Date.now();
        if (!this.stats) this.stats = setInterval(() => void this.measure(), STATS_MS);
        void this.measure();
        break;
      case "disconnected":
      case "failed":
        if (peer.state !== "connected" && peer.state !== "reconnecting") {
          if (peer.pc.connectionState === "failed") {
            if (c.group) this.drop(c, peer.device);
            else {
              this.send({ to: EVERYONE, kind: "end", reason: "failed" });
              void this.end("failed");
            }
          }
          break;
        }
        peer.state = "reconnecting";
        if (!c.group) c.state = "reconnecting";
        // The offerer restarts ICE (one side does, so the two never collide).
        if (peer.offerer && peer.pc.connectionState === "failed") void this.restart(peer);
        peer.lost ??= setTimeout(() => {
          if (c.group) {
            this.drop(c, peer.device);
            this.emit();
          } else {
            this.send({ to: EVERYONE, kind: "end", reason: "failed" });
            void this.end("completed");
          }
        }, RECONNECT_MS);
        break;
    }
    this.emit();
  }

  /** New network paths after the old ones broke (say, Wi-Fi to cellular). */
  private async restart(peer: Peer) {
    if (!peer.device) return;
    peer.described = false;
    await peer.pc.setLocalDescription(await peer.pc.createOffer({ iceRestart: true }));
    await waitForCandidates(peer.pc);
    peer.described = true;
    this.send({ to: peer.device, kind: "offer", video: false, sdp: peer.pc.localDescription!.sdp });
  }

  /** Relay credentials expire; renew them in time for a long call. */
  private scheduleRefresh() {
    const ttl = this.rt.iceTtlS;
    if (!ttl) return;
    this.later(Math.max(ttl - REFRESH_MARGIN_S, 60) * 1000, async () => {
      const c = this.call;
      if (!c) return;
      c.servers = await this.rt.iceServers(c.conversation, true);
      for (const peer of c.peers.values()) {
        peer.pc.setConfiguration({ ...peer.pc.getConfiguration(), iceServers: c.servers });
        if (peer.offerer && peer.path === "relayed") await this.restart(peer);
      }
      this.scheduleRefresh();
    });
  }

  private async measure() {
    const c = this.call;
    if (!c) return;
    for (const peer of c.peers.values()) {
      const report = await peer.pc.getStats();
      let pair: RTCIceCandidatePairStats | undefined;
      report.forEach((stat) => {
        if (stat.type === "transport" && stat.selectedCandidatePairId) pair = report.get(stat.selectedCandidatePairId);
      });
      if (!pair) {
        report.forEach((stat) => {
          if (stat.type === "candidate-pair" && stat.nominated && stat.state === "succeeded") pair = stat;
        });
      }
      if (!pair) continue;
      const local = report.get(pair.localCandidateId);
      const remote = report.get(pair.remoteCandidateId);
      peer.path = local?.candidateType === "relay" || remote?.candidateType === "relay" ? "relayed" : "direct";
      peer.rttMs = pair.currentRoundTripTime === undefined ? undefined : Math.round(pair.currentRoundTripTime * 1000);
    }
    this.emit();
  }

  // ---- Ending -------------------------------------------------------------

  private later(ms: number, work: () => void | Promise<void>) {
    this.timers.push(setTimeout(() => void work(), ms));
  }

  private clearTimers() {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers = [];
  }

  /** Closes one connection of a group call. */
  private drop(c: Call, device: string) {
    const peer = c.peers.get(device);
    if (!peer) return;
    clearTimeout(peer.lost);
    peer.pc.close();
    c.peers.delete(device);
    c.members.delete(device);
    this.shareUplink();
  }

  /** Stops media and every connection, without a trace in the history. */
  private close() {
    const c = this.call;
    this.clearTimers();
    clearInterval(this.stats);
    this.stats = undefined;
    for (const peer of c?.peers.values() ?? []) {
      clearTimeout(peer.lost);
      peer.pc.close();
    }
    for (const track of c?.local?.getTracks() ?? []) track.stop();
    this.call = undefined;
    this.emit();
  }

  /** Ends the call on this device and records it in the conversation. */
  private async end(outcome: CallRecord["outcome"], quiet = false) {
    const c = this.call;
    if (!c || c.state === "ended") return;
    if (quiet && c.state !== "incoming") this.send({ to: EVERYONE, kind: "end", reason: "failed" });
    const seconds = c.connectedAt ? Math.round((Date.now() - c.connectedAt) / 1000) : 0;
    const view = this.current();
    this.close();
    if (view) this.setView({ ...view, state: "ended", outcome, local: undefined, peers: [] });
    await this.rt.recordCall(c.conversation, { direction: c.direction, video: c.video, group: c.group, outcome, seconds });
    setTimeout(() => {
      if (this.current()?.id === c.id && this.current()?.state === "ended") this.setView(undefined);
    }, 1_500);
  }
}

/** A group call already holds as many devices as a mesh can carry. */
export class CallFull extends Error {}
/** Calls must be relayed, and no relay could be had. */
export class RelayUnavailable extends Error {}
