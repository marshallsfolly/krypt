// Before a file leaves this device: photos and videos lose their location,
// camera and editing metadata (in Rust, krypt_core::scrub), and get a small
// preview that travels inside the message. Other files go as they are.

import { fileLimits, mediaFormat, scrubImage, scrubMp4, scrubWebm } from "../core/krypt_wasm.js";

/** Largest image scrubbed whole (krypt_core::scrub::IMAGE_MAX); larger
 * photos are re-encoded instead. */
const IMAGE_MAX = 32 * 1024 * 1024;
/** Largest video metadata box (`moov`) read into memory. */
const BOX_MAX = 32 * 1024 * 1024;
/** Most top-level boxes walked in a video. */
const BOXES_MAX = 4096;
const THUMB_EDGE = 320;
/** Re-encoded photos are capped at this many pixels on the long edge. */
const REENCODE_EDGE = 4096;

export interface Prepared {
  blob: Blob;
  name: string;
  mediaType: string;
  width: number;
  height: number;
  thumbnail: Uint8Array;
}

/** A photo or video whose metadata could not be removed: not sent. */
export class NotScrubbed extends Error {
  constructor() {
    super("metadata could not be removed");
  }
}

const SCRUBBED_TYPES: Record<string, string> = {
  jpeg: "image/jpeg",
  png: "image/png",
  webp: "image/webp",
  gif: "image/gif",
  mp4: "video/mp4",
};
/** Largest WebM video cleaned (in memory, whole). */
const WEBM_MAX = 256 * 1024 * 1024;

/** A recorded voice message without the recorder's metadata: WebM (Opus,
 * from Chrome and Firefox) or MP4 (from Safari). Anything else is refused. */
export async function prepareVoice(recorded: Blob): Promise<{ blob: Blob; mediaType: "audio/webm" | "audio/mp4" }> {
  const bytes = new Uint8Array(await recorded.arrayBuffer());
  const webm = bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3;
  try {
    if (webm) {
      scrubWebm(bytes);
      return { blob: new Blob([bytes], { type: "audio/webm" }), mediaType: "audio/webm" };
    }
    if (mediaFormat(bytes.subarray(0, 64)) === "mp4") {
      scrubMp4(bytes);
      return { blob: new Blob([bytes], { type: "audio/mp4" }), mediaType: "audio/mp4" };
    }
  } catch {
    // Did not parse: refused below.
  }
  throw new NotScrubbed();
}

export async function prepare(file: File): Promise<Prepared> {
  const head = new Uint8Array(await file.slice(0, 64).arrayBuffer());
  const format = mediaFormat(head);
  let blob: Blob = file;
  let mediaType = file.type || "application/octet-stream";
  let name = file.name || "file";
  // By what the file is, not what it is called: a photo with no type, or the
  // wrong one, is cleaned like any other.
  if (format === "jpeg" || format === "png" || format === "webp" || format === "gif") {
    mediaType = SCRUBBED_TYPES[format]!;
    try {
      if (file.size > IMAGE_MAX) throw new NotScrubbed();
      const clean = scrubImage(new Uint8Array(await file.arrayBuffer())) as Uint8Array<ArrayBuffer>;
      blob = new Blob([clean], { type: mediaType });
    } catch {
      // Damaged or huge: drawing it again keeps the pixels and nothing else.
      blob = await reencode(file);
      mediaType = "image/jpeg";
      name = withExtension(name, "jpg");
    }
  } else if (format === "mp4") {
    blob = await scrubVideo(file);
    // QuickTime files keep their type; browsers play them as MP4.
    if (!mediaType.startsWith("video/")) mediaType = "video/mp4";
  } else if (format === "webm") {
    if (file.size > WEBM_MAX) throw new NotScrubbed();
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      scrubWebm(bytes);
    } catch {
      throw new NotScrubbed();
    }
    mediaType = mediaType.startsWith("audio/") ? "audio/webm" : "video/webm";
    blob = new Blob([bytes], { type: mediaType });
  } else if (format === "still" || mediaType.startsWith("image/")) {
    // HEIC, AVIF, TIFF…: only re-encoding is sure to drop their metadata.
    blob = await reencode(file);
    mediaType = "image/jpeg";
    name = withExtension(name, "jpg");
  } else if (mediaType.startsWith("video/")) {
    throw new NotScrubbed();
  }

  const preview = mediaType.startsWith("image/")
    ? await imagePreview(blob)
    : mediaType.startsWith("video/")
      ? await videoPreview(blob)
      : undefined;
  const limits = fileLimits();
  return {
    blob,
    name: clampUtf8(safeName(name), limits.nameMax),
    mediaType: mediaType.slice(0, limits.typeMax),
    width: preview?.width ?? 0,
    height: preview?.height ?? 0,
    thumbnail: preview?.thumbnail ?? new Uint8Array(),
  };
}

function withExtension(name: string, extension: string): string {
  const dot = name.lastIndexOf(".");
  return `${dot > 0 ? name.slice(0, dot) : name}.${extension}`;
}

/** Names are shown and used for saving: no paths, controls, or text-direction
 * tricks (`gpj.exe` shown as `exe.jpg`). */
export function safeName(name: string): string {
  const cleaned = name
    .replace(/[\u0000-\u001f\u007f‎‏‪-‮⁦-⁩]/g, "")
    .replace(/[\\/:*?"<>|]/g, "_")
    .trim();
  return cleaned === "" || cleaned === "." || cleaned === ".." ? "file" : cleaned;
}

function clampUtf8(text: string, max: number): string {
  const encoder = new TextEncoder();
  if (encoder.encode(text).length <= max) return text;
  let out = "";
  for (const ch of text) {
    if (encoder.encode(out + ch).length > max) break;
    out += ch;
  }
  return out;
}

/** Walks a video's top-level boxes by reading only their headers, and
 * scrubs the metadata boxes (and `moov`, which holds more) in memory. */
async function scrubVideo(file: File): Promise<Blob> {
  const pieces: BlobPart[] = [];
  let offset = 0;
  let kept = 0;
  for (let boxes = 0; offset < file.size; boxes++) {
    if (boxes >= BOXES_MAX) throw new NotScrubbed();
    const head = new Uint8Array(await file.slice(offset, offset + 16).arrayBuffer());
    if (head.length < 8) throw new NotScrubbed();
    const view = new DataView(head.buffer);
    let size = view.getUint32(0);
    const type = String.fromCharCode(...head.subarray(4, 8));
    let header = 8;
    if (size === 1) {
      if (head.length < 16) throw new NotScrubbed();
      size = Number(view.getBigUint64(8));
      header = 16;
    } else if (size === 0) {
      size = file.size - offset;
    }
    if (size < header || offset + size > file.size) throw new NotScrubbed();
    if (type === "moov" || type === "udta" || type === "meta" || type === "uuid") {
      if (size > BOX_MAX) throw new NotScrubbed();
      const box = new Uint8Array(await file.slice(offset, offset + size).arrayBuffer());
      try {
        scrubMp4(box);
      } catch {
        throw new NotScrubbed();
      }
      pieces.push(file.slice(kept, offset), box);
      kept = offset + size;
    }
    offset += size;
  }
  pieces.push(file.slice(kept));
  return new Blob(pieces, { type: file.type || "video/mp4" });
}

function canvasBlob(canvas: HTMLCanvasElement, quality: number): Promise<Blob> {
  return new Promise((resolve, reject) =>
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("encoding failed"))), "image/jpeg", quality),
  );
}

function draw(source: CanvasImageSource, width: number, height: number, edge: number): HTMLCanvasElement {
  const scale = Math.min(1, edge / Math.max(width, height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(width * scale));
  canvas.height = Math.max(1, Math.round(height * scale));
  canvas.getContext("2d")!.drawImage(source, 0, 0, canvas.width, canvas.height);
  return canvas;
}

async function reencode(file: Blob): Promise<Blob> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new NotScrubbed();
  }
  const canvas = draw(bitmap, bitmap.width, bitmap.height, REENCODE_EDGE);
  bitmap.close();
  return canvasBlob(canvas, 0.92);
}

async function thumbnail(source: CanvasImageSource, width: number, height: number): Promise<Uint8Array> {
  const max = fileLimits().thumbnailMax;
  for (const [edge, quality] of [
    [THUMB_EDGE, 0.7],
    [THUMB_EDGE, 0.5],
    [200, 0.5],
  ] as const) {
    const blob = await canvasBlob(draw(source, width, height, edge), quality);
    if (blob.size <= max) return new Uint8Array(await blob.arrayBuffer());
  }
  return new Uint8Array();
}

async function imagePreview(blob: Blob) {
  try {
    const bitmap = await createImageBitmap(blob);
    const out = {
      width: bitmap.width,
      height: bitmap.height,
      thumbnail: await thumbnail(bitmap, bitmap.width, bitmap.height),
    };
    bitmap.close();
    return out;
  } catch {
    return undefined;
  }
}

/** The first frame of a video, if this browser can decode it in time. */
async function videoPreview(blob: Blob) {
  const url = URL.createObjectURL(blob);
  const video = document.createElement("video");
  video.muted = true;
  video.playsInline = true;
  video.preload = "auto";
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out")), 5_000);
      video.onloadeddata = () => {
        video.currentTime = Math.min(0.5, (video.duration || 0) / 2);
      };
      video.onseeked = () => {
        clearTimeout(timer);
        resolve();
      };
      video.onerror = () => {
        clearTimeout(timer);
        reject(new Error("undecodable"));
      };
      video.src = url;
    });
    return {
      width: video.videoWidth,
      height: video.videoHeight,
      thumbnail: await thumbnail(video, video.videoWidth, video.videoHeight),
    };
  } catch {
    return undefined;
  } finally {
    video.removeAttribute("src");
    video.load();
    URL.revokeObjectURL(url);
  }
}
