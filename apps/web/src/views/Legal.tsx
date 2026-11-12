import { strings } from "../app/strings";

/** A sentence around links to the Terms and the Privacy Policy. They are
 * pages of their own, so they open beside the app instead of replacing it. */
export function LegalLinks(props: { words: string[] }) {
  return (
    <>
      {props.words[0]}
      <a class="link" href="/terms" target="_blank">
        {strings.legal.terms}
      </a>
      {props.words[1]}
      <a class="link" href="/privacy" target="_blank">
        {strings.legal.privacy}
      </a>
      {props.words[2]}
    </>
  );
}
