# Releases

krypt is a web app, so whoever serves krypt.chat could serve different code.
Releases make that hard and visible (decision 54):

- **Built in public.** A tag `vX.Y.Z` on github.com/marshallsfolly/krypt
  starts `.github/workflows/release.yml`: the sealed Nix build of the web app
  (`nix build .#webDist`), a manifest naming every file and its SHA-256,
  and GitHub's attestation that this workflow built it from that commit. The
  release stays a draft.
- **Signed offline.** The release key is on a YubiKey (an SSH key,
  `sk-ssh-ed25519@openssh.com`; the private half never leaves it). `just
  release-sign vX.Y.Z` checks the attestation, builds the same commit locally
  and checks it gives the same files, then signs the manifest (a touch of
  the key) and publishes the release. Nothing on GitHub can sign.
- **Deployed as signed.** `just edge-deploy vX.Y.Z` fetches the release,
  checks the signature, the attestation and every file, and uploads exactly
  those files, with the Worker built from the same commit.
- **Pinned in the browser.** The app's service worker holds the release
  key. It serves the app only from a copy whose manifest the key signed and
  whose every file matched, sets the release's own security headers on it,
  and takes a new release only if it is signed and newer. Anything else is
  refused: the app keeps running the release it has and shows a warning.
  Settings shows the running release.
- **Watched.** `.github/workflows/monitor.yml` checks every hour that
  krypt.chat serves exactly the latest signed release, and opens an issue if
  not.

## What it does not do

- **The first visit trusts the server.** Until the service worker is
  installed, the browser runs what krypt.chat sends.
- **The service worker itself comes from the server.** Browsers fetch it
  again at least once a day, and whoever controls krypt.chat could replace
  it. The app checks a replaced service worker against the signed release
  and warns if it is not the release's, but by then the replacement is
  installed.
- **The monitor sees what everyone is served**, not what one person might
  be served.

So a malicious server can still target someone, but it can no longer change
the app for everyone quietly, and a pinned device notices.

## Checking a release yourself

```sh
gh release download vX.Y.Z -R marshallsfolly/krypt
printf 'krypt-release namespaces="krypt-release" %s\n' "$(cut -d' ' -f1,2 apps/web/release-key.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I krypt-release -n krypt-release -s manifest.json.sig < manifest.json
gh attestation verify krypt-web.tar -R marshallsfolly/krypt
git checkout vX.Y.Z && nix build .#webDist
node apps/web/scripts/manifest.mjs check result manifest.json
node apps/web/scripts/manifest.mjs site https://krypt.chat manifest.json
```

## Making one

```sh
just release-keygen          # once: the key on the YubiKey; commit apps/web/release-key.pub
just release-tag vX.Y.Z      # tags HEAD and pushes the tag; CI builds a draft
just release-sign vX.Y.Z     # checks CI's build against a local one, signs, publishes
git checkout vX.Y.Z && just edge-deploy vX.Y.Z
```

A lost or replaced release key means a new key pinned in a new release:
devices pinned to the old key refuse it and keep warning until krypt.chat's
site data is cleared, which is the point.
