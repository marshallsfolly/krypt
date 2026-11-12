// A small, consistent icon set: 24px grid, 1.75 stroke, round joins.

import type { JSX } from "solid-js";

// Functions, not elements: an element is one DOM node, so an icon shown
// twice on a screen would appear only once.
const paths: Record<string, () => JSX.Element> = {
  plus: () => <path d="M12 5v14M5 12h14" />,
  back: () => <path d="M15 5l-7 7 7 7" />,
  send: () => <path d="M5 12h12M12 6l6 6-6 6" />,
  gear: () => (
    <>
      <path d="M10.5 4.96L10.68 2.59A9.5 9.5 0 0 1 13.32 2.59L13.5 4.96A7.2 7.2 0 0 1 15.92 5.96L17.72 4.41A9.5 9.5 0 0 1 19.59 6.28L18.04 8.08A7.2 7.2 0 0 1 19.04 10.5L21.41 10.68A9.5 9.5 0 0 1 21.41 13.32L19.04 13.5A7.2 7.2 0 0 1 18.04 15.92L19.59 17.72A9.5 9.5 0 0 1 17.72 19.59L15.92 18.04A7.2 7.2 0 0 1 13.5 19.04L13.32 21.41A9.5 9.5 0 0 1 10.68 21.41L10.5 19.04A7.2 7.2 0 0 1 8.08 18.04L6.28 19.59A9.5 9.5 0 0 1 4.41 17.72L5.96 15.92A7.2 7.2 0 0 1 4.96 13.5L2.59 13.32A9.5 9.5 0 0 1 2.59 10.68L4.96 10.5A7.2 7.2 0 0 1 5.96 8.08L4.41 6.28A9.5 9.5 0 0 1 6.28 4.41L8.08 5.96A7.2 7.2 0 0 1 10.5 4.96z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  card: () => (
    <>
      <rect x="3" y="5" width="18" height="14" rx="3" />
      <circle cx="9" cy="11" r="2" />
      <path d="M6 16c.8-1.5 1.8-2 3-2s2.2.5 3 2M14 10h4M14 13h3" />
    </>
  ),
  info: () => (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </>
  ),
  shield: () => <path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />,
  check: () => <path d="M5 12.5l4.5 4.5L19 7.5" />,
  copy: () => (
    <>
      <rect x="8" y="8" width="12" height="12" rx="2.5" />
      <path d="M16 8V6a2 2 0 00-2-2H6a2 2 0 00-2 2v8a2 2 0 002 2h2" />
    </>
  ),
  share: () => <path d="M12 15V4M8 8l4-4 4 4M5 13v5a2 2 0 002 2h10a2 2 0 002-2v-5" />,
  flame: () => <path d="M12 21c3.9 0 6.5-2.7 6.5-6.3 0-3.7-2.8-5.8-4-9.2-2.2 1.7-3 3.7-3 5.5-1.2-.6-2-1.8-2.2-3.2-1.5 1.6-3.8 4-3.8 7 0 3.6 2.6 6.2 6.5 6.2z" />,
  close: () => <path d="M6 6l12 12M18 6L6 18" />,
  attach: () => <path d="M20 11.5l-8.2 8.2a5 5 0 01-7.1-7.1l8.5-8.5a3.3 3.3 0 014.7 4.7l-8.5 8.5a1.7 1.7 0 01-2.4-2.4l7.9-7.9" />,
  download: () => <path d="M12 4v11M8 11l4 4 4-4M5 19h14" />,
  file: () => (
    <>
      <path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z" />
      <path d="M14 3v5h5" />
    </>
  ),
  play: () => <path d="M8 5.5v13l10.5-6.5L8 5.5z" />,
  phone: () => (
    <path d="M6.6 3.5h2.6l1.4 4-2 1.3a11 11 0 006.6 6.6l1.3-2 4 1.4v2.6a2 2 0 01-2.2 2A16.5 16.5 0 014.6 5.7a2 2 0 012-2.2z" />
  ),
  hangup: () => (
    <path d="M3.2 14.6l1.9 1.8 3.6-1.5v-2.4a11 11 0 016.6 0v2.4l3.6 1.5 1.9-1.8a2 2 0 00-.2-3A16.5 16.5 0 003.4 11.6a2 2 0 00-.2 3z" />
  ),
  video: () => (
    <>
      <rect x="3" y="6" width="12.5" height="12" rx="2.5" />
      <path d="M15.5 10.5L21 7.5v9l-5.5-3" />
    </>
  ),
  videoOff: () => (
    <>
      <path d="M15.5 13.5v2a2.5 2.5 0 01-2.5 2.5H5.5A2.5 2.5 0 013 15.5v-7A2.5 2.5 0 015.5 6H8M11.5 6h1.5a2.5 2.5 0 012.5 2.5v2L21 7.5v9" />
      <path d="M3 3l18 18" />
    </>
  ),
  mic: () => (
    <>
      <rect x="9" y="3" width="6" height="11" rx="3" />
      <path d="M5.5 11a6.5 6.5 0 0013 0M12 17.5V21" />
    </>
  ),
  micOff: () => (
    <>
      <path d="M15 10V6a3 3 0 00-5.8-1M9 9v2a3 3 0 004.6 2.5M5.5 11a6.5 6.5 0 0010.6 5M18.5 11a6.5 6.5 0 01-.6 2.7M12 17.5V21" />
      <path d="M3 3l18 18" />
    </>
  ),
  flip: () => <path d="M4 12a8 8 0 0113.7-5.6L20 9M20 4v5h-5M20 12a8 8 0 01-13.7 5.6L4 15M4 20v-5h5" />,
  next: () => <path d="M9 5l7 7-7 7" />,
  more: () => <path d="M6 12h.01M12 12h.01M18 12h.01" stroke-width="3" />,
  pause: () => <path d="M9 6v12M15 6v12" />,
  devices: () => (
    <>
      <rect x="2.5" y="5" width="13" height="10" rx="1.5" />
      <path d="M1.5 18h15M17.5 9.5h4v10h-4z" />
    </>
  ),
  lock: () => (
    <>
      <rect x="5" y="10.5" width="14" height="10" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 018 0v3" />
    </>
  ),
  bell: () => <path d="M6 16.5V11a6 6 0 0112 0v5.5l1.5 2h-15zM10 20.5a2 2 0 004 0" />,
  bellOff: () => (
    <>
      <path d="M6 16.5V11a6 6 0 019.4-4.9M18 11v5.5l1.5 2h-15M10 20.5a2 2 0 004 0" />
      <path d="M3 3l18 18" />
    </>
  ),
  search: () => (
    <>
      <circle cx="10.5" cy="10.5" r="6" />
      <path d="M15 15l5 5" />
    </>
  ),
  archive: () => (
    <>
      <rect x="3" y="4" width="18" height="5" rx="1" />
      <path d="M5 9v10h14V9M10 13h4" />
    </>
  ),
  palette: () => (
    <>
      <path d="M12 3a9 9 0 100 18c1.2 0 1.8-.8 1.8-1.7 0-1.3-1.3-1.7-1.3-3 0-1 .8-1.8 1.8-1.8H17a4 4 0 004-4C21 6.6 17 3 12 3z" />
      <circle cx="7.5" cy="11" r="1" />
      <circle cx="10.5" cy="7.5" r="1" />
      <circle cx="15" cy="7.5" r="1" />
    </>
  ),
  timer: () => (
    <>
      <circle cx="12" cy="13" r="8" />
      <path d="M12 9v4l2.5 2.5M9.5 2.5h5" />
    </>
  ),
  scan: () => (
    <>
      <path d="M4 8V6a2 2 0 012-2h2M16 4h2a2 2 0 012 2v2M20 16v2a2 2 0 01-2 2h-2M8 20H6a2 2 0 01-2-2v-2" />
      <path d="M8 12h8" />
    </>
  ),
};

export function Icon(props: { name: keyof typeof paths; size?: number; label?: string }) {
  return (
    <svg
      class="icon"
      width={props.size ?? 22}
      height={props.size ?? 22}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      role={props.label ? "img" : undefined}
      aria-label={props.label}
      aria-hidden={props.label ? undefined : true}
    >
      {paths[props.name]!()}
    </svg>
  );
}
