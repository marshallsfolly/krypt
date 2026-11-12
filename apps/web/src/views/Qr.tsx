import { createMemo } from "solid-js";
import { qrCode } from "../core/krypt_wasm.js";

const QUIET = 4;

/** A QR code as one SVG path. Always dark on light, in every theme: many
 * scanners cannot read an inverted code. */
export function Qr(props: { text: string; label: string }) {
  const code = createMemo(() => {
    const { size, modules } = qrCode(props.text);
    // One horizontal run per path segment keeps the path short.
    let d = "";
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; ) {
        if (!modules[y * size + x]) {
          x++;
          continue;
        }
        let run = 1;
        while (x + run < size && modules[y * size + x + run]) run++;
        d += `M${x + QUIET} ${y + QUIET}h${run}v1h-${run}z`;
        x += run;
      }
    }
    return { d, extent: size + 2 * QUIET };
  });
  return (
    <svg
      class="qr"
      viewBox={`0 0 ${code().extent} ${code().extent}`}
      role="img"
      aria-label={props.label}
      shape-rendering="crispEdges"
    >
      <rect width="100%" height="100%" fill="#fff" />
      <path d={code().d} fill="#000" />
    </svg>
  );
}
