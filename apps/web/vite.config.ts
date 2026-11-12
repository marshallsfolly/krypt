import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";
import solid from "vite-plugin-solid";

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

// The release key the app and its service worker pin (docs/releases.md):
// the committed public key, or a test key (KRYPT_RELEASE_KEY_FILE). With
// none, a development build: nothing is pinned.
const keyFile = process.env.KRYPT_RELEASE_KEY_FILE ?? here("./release-key.pub");
const releaseKey = existsSync(keyFile) ? readFileSync(keyFile, "utf8").trim() : "";

/** The headers public/_headers sets on every path (its `/*` block). */
function securityHeaders(): Record<string, string> {
  const out: Record<string, string> = {};
  let inAll = false;
  for (const line of readFileSync(here("./public/_headers"), "utf8").split("\n")) {
    if (!line.startsWith(" ")) inAll = line.trim() === "/*";
    else if (inAll && line.includes(":")) {
      const at = line.indexOf(":");
      out[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
    }
  }
  return out;
}

/** dist/sw.js: src/sw.js with the verifier inlined, the key pinned and the
 * release's security headers fixed. */
function serviceWorker(): Plugin {
  const build = () => {
    const verify = readFileSync(here("./src/release/verify.js"), "utf8").replace(/^export /gm, "");
    return readFileSync(here("./src/sw.js"), "utf8")
      .replace("/*__KRYPT_VERIFY__*/", () => verify)
      .replace('"__KRYPT_RELEASE_KEY__"', () => JSON.stringify(releaseKey))
      .replace('"__KRYPT_HEADERS__"', () => JSON.stringify(securityHeaders()));
  };
  return {
    name: "krypt-service-worker",
    configureServer(server) {
      server.middlewares.use("/sw.js", (_request, response) => {
        response.setHeader("content-type", "text/javascript");
        response.end(build());
      });
    },
    generateBundle() {
      this.emitFile({ type: "asset", fileName: "sw.js", source: build() });
    },
  };
}

// The mailbox is served from the same origin as the app (one Worker serves
// both), so development proxies /v1 to the local edge (`just edge-dev`).
export default defineConfig({
  plugins: [solid(), serviceWorker()],
  define: { __KRYPT_RELEASE_KEY__: JSON.stringify(releaseKey) },
  server: { proxy: { "/v1": { target: "http://127.0.0.1:8788", ws: true } } },
  build: { target: "es2022", assetsInlineLimit: 0 },
});
