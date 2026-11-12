import type { AppState } from "../app/state";

/** A person's mark: initials on a color derived from their identity, so
 * the same person looks the same everywhere. Themes decide the shape
 * (circle, morphing blob) or hide it (Swiss sets names in display type). */
export function Avatar(props: { app: AppState; identity?: string; group?: { id: string; title: string } }) {
  const seed = () => props.group?.id ?? props.identity;
  const hue = () => (seed() ? parseInt(seed()!.slice(0, 4), 16) % 360 : 0);
  const initials = () => {
    if (props.group) {
      const words = props.group.title.trim().split(/[\s,]+/).filter(Boolean);
      return ((words[0]?.[0] ?? "#") + (words[1]?.[0] ?? "")).toUpperCase();
    }
    if (!props.identity) return "…";
    const name = props.app.people[props.identity]?.name;
    if (name) {
      const words = name.trim().split(/\s+/);
      return (words[0]![0]! + (words[1]?.[0] ?? "")).toUpperCase();
    }
    return props.identity.slice(0, 2).toUpperCase();
  };
  return (
    <span class="avatar" style={{ "--hue": String(hue()) }} aria-hidden="true">
      {initials()}
    </span>
  );
}
