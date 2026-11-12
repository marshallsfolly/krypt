// The mailbox: one WebSocket per log the device follows. New entries are
// pushed over it, and requests for that log ride the same socket (a
// twentieth of an HTTP request's cost at the edge). With no open socket, a
// request goes over HTTP. Every (re)connect tells the device to fetch what
// it missed.

const PING_MS = 30_000; // Cloudflare closes sockets idle for 100 s.
const BACKOFF_MIN_MS = 500;
const BACKOFF_MAX_MS = 30_000;
const HEADER_SIZE = 64;
/** Frame kinds the app reads itself (krypt_wire::frame::Kind). */
export const KIND_ACCEPTED = 16;
export const KIND_HEADER = 22;

/** A frame's kind and body (the header's checksums were the server's to
 * check; what matters here is checked by the core). */
export function readFrame(frame: Uint8Array): { kind: number; body: Uint8Array } | undefined {
  if (frame.length < HEADER_SIZE) return undefined;
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const length = view.getUint32(36, true);
  if (HEADER_SIZE + length !== frame.length) return undefined;
  return { kind: frame[35]!, body: frame.subarray(HEADER_SIZE) };
}

/** Sends one frame over HTTP and returns the answer. */
export async function exchange(base: string, frame: Uint8Array<ArrayBuffer>): Promise<{ kind: number; body: Uint8Array } | undefined> {
  const response = await fetch(`${base}/v1/frame`, {
    method: "POST",
    body: frame,
    headers: { "content-type": "application/octet-stream" },
  });
  if (!response.ok) return undefined;
  return readFrame(new Uint8Array(await response.arrayBuffer()));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

class Follow {
  socket?: WebSocket;
  private ping?: ReturnType<typeof setInterval>;
  private retry?: ReturnType<typeof setTimeout>;
  private backoff = BACKOFF_MIN_MS;
  private closed = false;

  constructor(
    private url: string,
    /** The route this socket follows (hex): it speaks for no other. */
    private route: string,
    private onFrame: (frame: Uint8Array) => void,
    private onConnected: () => void,
  ) {
    this.connect();
  }

  get open(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  private connect() {
    const socket = new WebSocket(this.url);
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    socket.onopen = () => {
      this.backoff = BACKOFF_MIN_MS;
      this.ping = setInterval(() => socket.send("ping"), PING_MS);
      this.onConnected();
    };
    socket.onmessage = (event) => {
      if (!(event.data instanceof ArrayBuffer)) return;
      const frame = new Uint8Array(event.data);
      // A frame naming another route is not this log's to tell.
      if (frame.length < HEADER_SIZE || hex(frame.subarray(HEADER_SIZE - 16, HEADER_SIZE)) !== this.route) return;
      this.onFrame(frame);
    };
    socket.onclose = () => {
      clearInterval(this.ping);
      if (this.closed) return;
      // Jittered, so devices that lost the same connection spread out.
      const delay = this.backoff * (1 + Math.random() / 4);
      this.backoff = Math.min(this.backoff * 2, BACKOFF_MAX_MS);
      this.retry = setTimeout(() => this.connect(), delay);
    };
  }

  close() {
    this.closed = true;
    clearTimeout(this.retry);
    clearInterval(this.ping);
    this.socket?.close();
  }
}

export class Mailbox {
  private follows = new Map<string, Follow>();
  private wsBase: string;

  constructor(
    private base: string,
    private onFrame: (frame: Uint8Array) => void,
    private onConnected: () => void,
  ) {
    this.wsBase = base.replace(/^http/, "ws");
  }

  /** Follows exactly `routes`: opens sockets for new ones, closes the rest. */
  follow(routes: string[]) {
    const wanted = new Set(routes);
    for (const [route, follow] of this.follows) {
      if (!wanted.has(route)) {
        follow.close();
        this.follows.delete(route);
      }
    }
    for (const route of wanted) {
      if (!this.follows.has(route)) {
        this.follows.set(route, new Follow(`${this.wsBase}/v1/ws/${route}`, route, this.onFrame, this.onConnected));
      }
    }
  }

  /** `frame` is a JS-owned copy (wasm-bindgen copies out of wasm memory). */
  send(frame: Uint8Array<ArrayBuffer>) {
    const route = hex(frame.subarray(HEADER_SIZE - 16, HEADER_SIZE));
    const follow = this.follows.get(route);
    if (follow?.open) {
      follow.socket!.send(frame);
      return;
    }
    // The device retries on its own timer if this fails.
    fetch(`${this.base}/v1/frame`, {
      method: "POST",
      body: frame,
      headers: { "content-type": "application/octet-stream" },
    })
      .then(async (response) => {
        if (response.status === 200) this.onFrame(new Uint8Array(await response.arrayBuffer()));
      })
      .catch(() => {});
  }

  /** Sends `frame` only if its log's socket is open, else drops it: for
   * signals (typing, online), which only matter to whoever is connected. */
  sendLive(frame: Uint8Array<ArrayBuffer>) {
    const route = hex(frame.subarray(HEADER_SIZE - 16, HEADER_SIZE));
    const follow = this.follows.get(route);
    if (follow?.open) follow.socket!.send(frame);
  }

  close() {
    for (const follow of this.follows.values()) follow.close();
    this.follows.clear();
  }
}
