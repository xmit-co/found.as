#!/usr/bin/env node
// Publishes the found.as landing page and its og:image through the found.as
// signed-CBOR protocol — the same opcode-1 record the editor writes (src/api.ts
// updateData):
//
//   POST /api  <-  CBOR([ 1, pubKey, sign(CBOR([now, path, CBOR(priv), CBOR(pub)])) ])
//
// The page key is PBKDF2(password, "found.as/<path>", 100k, SHA-256) used as an
// Ed25519 seed (src/api.ts deriveKP). Two records are written, each keyed by its
// own path with the same password:
//   • the landing HTML  -> found.as/<path>      (Type.HTML_PAGE)
//   • the og:image PNG  -> found.as/<ogPath>    (Type.BYTES)
// A raw HTML page's subresources aren't served, so the image is its own page.
//
// Password: FOUND_AS_PW, else ~/.found.as, else prompted on a TTY.
// Env:
//   FOUND_AS_PATH     landing path   (default "" = the found.as root)
//   FOUND_AS_OG_PATH  og image path  (default "og")
//   FOUND_AS_API      API endpoint   (default https://be.found.as/api)
//   INTER_FONT        Inter font file for resvg (set by the nix devShell)
// Flags:
//   --dry-run         build + self-verify + write /tmp/found-og.png, do NOT POST

import { readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { encode, decode } from "cbor-x";
import nacl from "tweetnacl";

const HERE = dirname(fileURLToPath(import.meta.url));
const TYPE_HTML_PAGE = 0; // src/types.ts: enum Type { HTML_PAGE, MARKDOWN_PAGE, REDIR, BYTES, LINK_TREE }
const TYPE_BYTES = 3;

const landingPath = process.env.FOUND_AS_PATH ?? "";
const ogPath = process.env.FOUND_AS_OG_PATH ?? "og";
const api = process.env.FOUND_AS_API ?? "https://be.found.as/api";
const font = process.env.INTER_FONT;
const dryRun = process.argv.includes("--dry-run");
const enc = new TextEncoder();

const die = (msg) => {
  console.error(`✗ ${msg}`);
  process.exit(1);
};

if (!font) die("INTER_FONT is not set — run inside `nix develop`.");

// 1. Rasterize og.svg -> PNG bytes (stdout, no temp file).
const r = spawnSync(
  "resvg",
  ["--skip-system-fonts", "--use-font-file", font, join(HERE, "og.svg"), "-c"],
  { maxBuffer: 64 << 20 },
);
if (r.status !== 0) die(`resvg failed: ${r.stderr?.toString().trim() || r.error}`);
const png = new Uint8Array(r.stdout);
if (png[0] !== 0x89 || png[1] !== 0x50) die("resvg did not emit a PNG.");

// 2. Cache-busting version from the bytes (src/image.ts subVersion).
const version = createHash("sha256").update(png).digest("hex").slice(0, 8);

// 3. Landing HTML, with the og:image URL pinned to this render.
let html = await readFile(join(HERE, "landing.html"), "utf8");
const ogRef = 'content="https://found.as/og"';
if (!html.includes(ogRef)) die("landing.html has no og:image reference to version.");
html = html.replace(ogRef, `content="https://found.as/og?v=${version}"`);

// 4. Page key — PBKDF2 -> Ed25519 seed, mirroring src/api.ts deriveKP.
async function deriveKeyPair(path, pw) {
  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(pw),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: enc.encode(`found.as/${path}`),
      iterations: 100000,
    },
    material,
    256,
  );
  return nacl.sign.keyPair.fromSeed(new Uint8Array(bits));
}

function promptHidden(query) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => rl.output.write(s.includes(query) ? query : "*");
    rl.question(query, (answer) => {
      rl.output.write("\n");
      rl.close();
      resolve(answer);
    });
  });
}

async function resolvePassword() {
  if (process.env.FOUND_AS_PW) return process.env.FOUND_AS_PW;
  try {
    const fromFile = (await readFile(join(homedir(), ".found.as"), "utf8")).trim();
    if (fromFile) return fromFile;
  } catch {
    // fall through to prompt
  }
  if (process.stdin.isTTY) return promptHidden("found.as password: ");
  die("No password: set FOUND_AS_PW or ~/.found.as, or run on a TTY.");
}

// 5. Build a signed opcode-1 request (src/api.ts updateData) and POST it.
async function publishRecord(path, priv, pub, pw) {
  const kp = await deriveKeyPair(path, pw);
  const inner = encode([Date.now() / 1000, path, encode(priv), encode(pub)]);
  const signed = nacl.sign(inner, kp.secretKey);
  const body = encode([1, kp.publicKey, signed]);

  // Self-check: the signature opens and the inner payload round-trips.
  const opened = nacl.sign.open(signed, kp.publicKey);
  if (!opened || decode(opened).length !== 4) die(`signature self-check failed for /${path}`);

  if (dryRun) {
    console.log(`  would publish /${path || "(root)"} — ${body.length} bytes`);
    return;
  }
  // The editor posts from be.found.as, so send that Origin; the body is raw
  // CBOR (the browser sets no Content-Type for a byte-array body).
  const res = await fetch(api, {
    method: "POST",
    headers: { Origin: "https://be.found.as" },
    body,
  });
  if (!res.ok) die(`/${path}: ${res.status} ${(await res.text()).trim()}`);
}

const pw = await resolvePassword();

const landingPriv = { type: TYPE_HTML_PAGE, md: "", html, redir: "" };
const landingPub = { html };
const ogPriv = { type: TYPE_BYTES, md: "", html: "", redir: "" };
const ogPub = { bytes: png, mime: "image/png" };

console.log(`og image  : ${png.length} bytes, v=${version}`);

if (dryRun) {
  await writeFile("/tmp/found-og.png", png);
  console.log("dry-run   : wrote /tmp/found-og.png");
}

// Publish the image first, so the page never references a missing preview.
await publishRecord(ogPath, ogPriv, ogPub, pw);
await publishRecord(landingPath, landingPriv, landingPub, pw);

if (!dryRun) {
  console.log("✓ published");
  console.log(`  https://found.as/${landingPath}`);
  console.log(`  https://found.as/${ogPath}`);
}
