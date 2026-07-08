import { normalizePrivate } from "./linktree";
import { FourOFour, FourXX, Private, Public } from "./types";
import { subtle, textEncoder } from "./util";
import { decode, encode } from "cbor-x";
import { SignKeyPair, sign } from "tweetnacl";

export let postSingleton: AbortController | null = null;

export async function post(body: any) {
  if (postSingleton && !postSingleton.signal.aborted) {
    postSingleton.abort();
  }
  postSingleton = new AbortController();
  return fetch("/api", {
    method: "POST",
    body: encode(body),
    signal: postSingleton.signal,
  });
}

export async function updateData(
  keyPair: SignKeyPair,
  path: string,
  priv: Private,
  pub: Public,
): Promise<void> {
  const response = await post([
    1,
    keyPair.publicKey,
    sign(
      encode([new Date().getTime() / 1000, path, encode(priv), encode(pub)]),
      keyPair.secretKey,
    ),
  ]);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

export async function updatePw(
  keyPair: SignKeyPair,
  path: string,
  newPw: string,
): Promise<void> {
  const newKey = await deriveKP(path, newPw);
  const response = await post([
    3,
    keyPair.publicKey,
    sign(
      encode([new Date().getTime() / 1000, path, newKey.publicKey]),
      keyPair.secretKey,
    ),
  ]);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

export async function renamePage(
  keyPair: SignKeyPair,
  path: string,
  newPath: string,
  pw: string,
): Promise<void> {
  // The page key is derived from the path, so the new address is keyed with the
  // key its own password derives — the same password keeps working after.
  const newKey = await deriveKP(newPath, pw);
  const response = await post([
    8,
    keyPair.publicKey,
    sign(
      encode([new Date().getTime() / 1000, path, newPath, newKey.publicKey]),
      keyPair.secretKey,
    ),
  ]);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

export async function deletePage(
  keyPair: SignKeyPair,
  path: string,
): Promise<void> {
  const response = await post([
    9,
    keyPair.publicKey,
    sign(encode([new Date().getTime() / 1000, path]), keyPair.secretKey),
  ]);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

export async function fetchData(
  keyPair: SignKeyPair,
  path: string,
): Promise<Private> {
  const response = await post([
    2,
    keyPair.publicKey,
    sign(encode([new Date().getTime() / 1000, path]), keyPair.secretKey),
  ]);
  if (!response.ok) {
    if (response.status === 404) {
      throw new FourOFour(await response.text());
    }
    if (response.status >= 400 && response.status < 500) {
      throw new FourXX(await response.text());
    }
    throw new Error(`${response.status} (${await response.text()})`);
  }
  return normalizePrivate(decode(new Uint8Array(await response.arrayBuffer())));
}

export interface DomainStatus {
  label: string;
  target: string;
  apex: boolean;
  mapped: boolean;
  conflict?: boolean;
  bound: boolean;
  reachable: boolean;
  reachError?: string;
  cert: boolean;
  certError?: string;
  certPaused?: boolean;
}

// Custom-domain requests bypass the aborting post() singleton: status polling
// must never cancel an in-flight publish or fetch.
export async function domainRequest(
  code: number,
  keyPair: SignKeyPair,
  path: string,
  domain: string,
): Promise<Response> {
  const response = await fetch("/api", {
    method: "POST",
    body: encode([
      code,
      keyPair.publicKey,
      sign(
        encode([new Date().getTime() / 1000, path, domain]),
        keyPair.secretKey,
      ),
    ]),
  });
  if (!response.ok) {
    throw new Error((await response.text()).trim());
  }
  return response;
}

export async function mapCustomDomain(
  keyPair: SignKeyPair,
  path: string,
  domain: string,
): Promise<void> {
  await domainRequest(4, keyPair, path, domain);
}

export async function unmapCustomDomain(
  keyPair: SignKeyPair,
  path: string,
  domain: string,
): Promise<void> {
  await domainRequest(5, keyPair, path, domain);
}

export async function customDomainStatus(
  keyPair: SignKeyPair,
  path: string,
  domain: string,
): Promise<DomainStatus> {
  const response = await domainRequest(6, keyPair, path, domain);
  return decode(new Uint8Array(await response.arrayBuffer()));
}

export async function listCustomDomains(
  keyPair: SignKeyPair,
  path: string,
): Promise<string[]> {
  const response = await domainRequest(7, keyPair, path, "");
  return decode(new Uint8Array(await response.arrayBuffer())) ?? [];
}

export function normalizeDomainInput(value: string): string | null {
  let v = value.trim().toLowerCase();
  if (!v) {
    return null;
  }
  try {
    // URL parsing accepts pasted addresses and converts unicode to punycode.
    v = new URL(v.includes("://") ? v : `http://${v}`).hostname;
  } catch {
    return null;
  }
  v = v.replace(/\.$/, "");
  if (!v.includes(".") || v.includes(":")) {
    return null;
  }
  return v;
}

export interface PendingDomain {
  domain: string;
  state: "waiting" | "securing";
  target: string;
  label: string;
  isApex: boolean;
}

export async function deriveKP(path: string, pw: string) {
  return sign.keyPair.fromSeed(
    new Uint8Array(
      await subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: textEncoder.encode(`found.as/${path}`),
          iterations: 100000,
        },
        await subtle.importKey("raw", textEncoder.encode(pw), "PBKDF2", false, [
          "deriveBits",
        ]),
        256,
      ),
    ),
  );
}

// True when two keypairs are the same page credential.
export function sameKeyPair(a: SignKeyPair, b: SignKeyPair): boolean {
  return (
    a.publicKey.length === b.publicKey.length &&
    a.publicKey.every((byte, i) => byte === b.publicKey[i])
  );
}

export interface IndieAuthMintParams {
  me: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope: string;
}

// mintIndieAuthCode signs an IndieAuth approval with the page key and asks the
// backend for a single-use authorization code. The backend re-resolves `me` to a
// page and rejects the request unless this key owns it.
export async function mintIndieAuthCode(
  keyPair: SignKeyPair,
  p: IndieAuthMintParams,
): Promise<{ code: string; me: string }> {
  const response = await fetch("/api", {
    method: "POST",
    body: encode([
      10,
      keyPair.publicKey,
      sign(
        encode([
          new Date().getTime() / 1000,
          p.me,
          p.clientId,
          p.redirectUri,
          p.codeChallenge,
          p.codeChallengeMethod,
          p.scope,
        ]),
        keyPair.secretKey,
      ),
    ]),
  });
  if (!response.ok) {
    throw new Error((await response.text()).trim() || `${response.status}`);
  }
  return decode(new Uint8Array(await response.arrayBuffer()));
}

// resolveIndieAuthMe turns an identity URL (used when it's a custom domain,
// where the page path isn't in the URL) into the found.as page path whose key
// the consent screen must load.
export async function resolveIndieAuthMe(
  me: string,
): Promise<{ path: string; me: string }> {
  const response = await fetch(
    `/indieauth/resolve?me=${encodeURIComponent(me)}`,
  );
  if (!response.ok) {
    throw new Error("This address isn't a found.as page.");
  }
  return response.json();
}
