import { createSignal, For, Index, Show, type JSX } from "solid-js";
import { haptic } from "../app/appearance";
import { Icon } from "../app/icons";
import { strings } from "../app/strings";

/** A QR code's look (not a real one): finder squares in three corners, a
 * gap around them, and a fixed scatter of modules. */
const QR = 13;
const qrModule = (x: number, y: number) => {
  for (const [cx, cy] of [
    [2, 2],
    [QR - 3, 2],
    [2, QR - 3],
  ] as const) {
    const d = Math.max(Math.abs(x - cx), Math.abs(y - cy));
    if (d <= 3) return d === 2 || d === 0;
  }
  return (x * 31 + y * 17 + x * y * 7) % 7 < 3;
};

function Art(props: { kind: number }) {
  switch (props.kind) {
    case 0:
      return (
        <div class="tour-art tour-orb">
          <span class="tour-ring" />
          <span class="tour-ring" />
          <span class="tour-ring" />
          <span class="tour-core">
            <Icon name="lock" size={36} />
          </span>
        </div>
      );
    case 1:
      return (
        <div class="tour-art tour-card">
          <div class="tour-qr">
            <Index each={Array.from({ length: QR * QR })}>{(_, i) => <span classList={{ on: qrModule(i % QR, Math.floor(i / QR)) }} />}</Index>
            <span class="tour-scan" />
          </div>
          <span class="tour-card-name label">@you</span>
        </div>
      );
    case 2:
      return (
        <div class="tour-art tour-verify">
          <For each={["left", "right"]}>
            {(side) => (
              <div class={`tour-phone ${side}`}>
                <For each={["37021", "88412", "05993", "61447"]}>{(n) => <span class="meta">{n}</span>}</For>
              </div>
            )}
          </For>
          <span class="tour-match">
            <Icon name="check" size={22} />
          </span>
        </div>
      );
    default:
      return (
        <div class="tour-art tour-keys">
          <span class="tour-core">
            <Icon name="shield" size={34} />
          </span>
          <span class="tour-chip a">
            <Icon name="lock" size={18} />
          </span>
          <span class="tour-chip b">
            <Icon name="devices" size={18} />
          </span>
          <span class="tour-chip c">
            <Icon name="flame" size={18} />
          </span>
        </div>
      );
  }
}

/** How krypt works, in four swipeable pages, then `end`: the first thing a
 * new person sees, and again from Settings. Swipe, or Next; Skip goes
 * straight to the end. */
export function Tour(props: { end: JSX.Element }) {
  const pages = strings.tour.pages;
  const last = pages.length;
  const [page, setPage] = createSignal(0);
  let scroller!: HTMLDivElement;

  const go = (to: number) => scroller.scrollTo({ left: to * scroller.clientWidth, behavior: "smooth" });
  const onScroll = () => {
    const at = Math.round(scroller.scrollLeft / Math.max(1, scroller.clientWidth));
    if (at !== page()) {
      setPage(at);
      haptic("sheetDetent");
    }
  };

  return (
    <div class="tour" data-page={page()}>
      <header class="tour-top">
        <span class="brand">{strings.appName}</span>
        <Show when={page() < last}>
          <button class="btn ghost" onClick={() => go(last)}>
            {strings.skip}
          </button>
        </Show>
      </header>
      <div class="tour-pages" ref={scroller} onScroll={onScroll} tabindex="-1">
        <For each={pages}>
          {(p, i) => (
            <section class="tour-page" data-active={page() === i()} inert={page() !== i() || undefined}>
              <Art kind={i()} />
              <h1 class="display">{p.title}</h1>
              <p class="body muted">{p.body}</p>
            </section>
          )}
        </For>
        <section class="tour-page tour-end" data-active={page() === last} inert={page() !== last || undefined}>
          {props.end}
        </section>
      </div>
      <footer class="tour-foot" classList={{ hidden: page() === last }}>
        <div class="tour-dots" role="tablist" aria-label={strings.tour.progress}>
          <Index each={[...pages, null]}>
            {(_, i) => (
              <button
                role="tab"
                class="tour-dot"
                aria-selected={page() === i}
                aria-label={strings.tour.page(i + 1, last + 1)}
                onClick={() => go(i)}
              />
            )}
          </Index>
        </div>
        <button class="btn wide" onClick={() => go(page() + 1)}>
          {strings.tour.next}
          <Icon name="next" size={18} />
        </button>
      </footer>
    </div>
  );
}
