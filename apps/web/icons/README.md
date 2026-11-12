Sources for the app icons and link-preview card in `public/`. Regenerate the
icons with `just web-icons` and the card with `just web-og`.

The mark is two rings whose overlap is filled: two people, and the key only
they share.

- `favicon.svg`: the browser-tab icon (`public/icon.svg`), with the mark larger
  and heavier so it holds up at 16 and 32 pixels.
- `mark.svg`: the rounded tile for the 192 and 512 icons.
- `square.svg`: full-bleed with the mark inside the maskable safe zone, for
  Android's adaptive icons and iOS (which applies its own corner mask).
- `og.html`: the 1200 × 630 card shown when someone shares a krypt.chat link
  (`public/og.png`). It loads Geist from `node_modules`, never from a CDN.
