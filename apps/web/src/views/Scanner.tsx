import { onCleanup, onMount } from "solid-js";

interface Detected {
  rawValue: string;
}
interface BarcodeDetectorLike {
  detect(source: HTMLVideoElement): Promise<Detected[]>;
}
declare const BarcodeDetector: { new (options: { formats: string[] }): BarcodeDetectorLike } | undefined;

/** Whether this browser can scan QR codes itself (Chrome on Android and
 * desktop). Elsewhere, the phone's camera app opens the card's link. */
export const canScan = () => typeof BarcodeDetector !== "undefined" && !!navigator.mediaDevices;

/** The card in a scanned value: a krypt.chat link or the card text. */
export function cardIn(value: string): string | undefined {
  const link = /#add=(.+)$/.exec(value);
  let text: string;
  try {
    text = decodeURIComponent(link ? link[1]! : value).trim();
  } catch {
    // Some other code with a stray `%`: keep scanning.
    return undefined;
  }
  return /^krypt:/i.test(text) ? text : undefined;
}

/** A link code (to link this identity's new device) in a scanned value. */
export function linkIn(value: string): string | undefined {
  const text = value.trim();
  return /^krypt-link2?:/i.test(text) ? text : undefined;
}

/** The camera, looking for a card (or, with `accept`, something else).
 * Stops as soon as one is found. */
export function Scanner(props: {
  onCard: (card: string) => void;
  onError: () => void;
  accept?: (value: string) => string | undefined;
}) {
  let video!: HTMLVideoElement;
  let stream: MediaStream | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;

  const stop = () => {
    stopped = true;
    clearTimeout(timer);
    stream?.getTracks().forEach((t) => t.stop());
  };

  onMount(async () => {
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      if (stopped) return stop();
      video.srcObject = stream;
      await video.play();
      const detector = new BarcodeDetector!({ formats: ["qr_code"] });
      const look = async () => {
        if (stopped) return;
        const accept = props.accept ?? cardIn;
        const found = (await detector.detect(video).catch(() => [])).map((d) => accept(d.rawValue)).find(Boolean);
        if (found) {
          stop();
          props.onCard(found);
        } else {
          timer = setTimeout(look, 200);
        }
      };
      void look();
    } catch {
      stop();
      props.onError();
    }
  });
  onCleanup(stop);

  return <video ref={video} class="scanner" muted playsinline aria-hidden="true" />;
}
