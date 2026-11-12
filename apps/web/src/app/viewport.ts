// The app always fills exactly what is visible, so opening the on-screen
// keyboard never zooms, pans or scrolls the page: the app shrinks to the space
// above the keyboard with its header and composer in place, as a native app
// does. Chrome and Firefox on Android shrink the page themselves
// (interactive-widget=resizes-content in index.html); Safari leaves the page
// full height under the keyboard and pans it, so the app follows the visual
// viewport instead: --vv-top and --vv-bottom are how much of the page is out
// of sight above and below (the keyboard), and --vv-height what is left.

export function fitViewport() {
  const visual = window.visualViewport;
  if (!visual) return;
  const root = document.documentElement.style;
  const fit = () => {
    // Pinch zoom (Safari allows it whatever the page says) is not a keyboard:
    // leave the app as it is.
    const zoomed = visual.scale > 1.01;
    const page = document.documentElement.clientHeight;
    const top = zoomed ? 0 : Math.max(0, visual.offsetTop);
    const height = zoomed ? page : Math.min(page, visual.height);
    root.setProperty("--vv-top", `${top}px`);
    root.setProperty("--vv-bottom", `${Math.max(0, page - top - height)}px`);
    root.setProperty("--vv-height", `${height}px`);
  };
  visual.addEventListener("resize", fit);
  visual.addEventListener("scroll", fit);
  window.addEventListener("resize", fit);
  fit();
}
