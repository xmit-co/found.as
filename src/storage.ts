import { SignKeyPair, sign } from "tweetnacl";

// Remembering a page stores its derived private key (not the password) in this
// browser's localStorage, so it opens without re-entering the password. It is
// the page's full edit credential — offered per device, and forgettable.
export const REMEMBERED_KEY = "found.as:remembered";

export interface RememberedPage {
  path: string;
  key: string; // base64 of the Ed25519 secret key
}

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(value: string): Uint8Array {
  const s = atob(value);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

// URL-safe base64 (for the recovery link's #fragment key): no +, /, or =.
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return fromBase64(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
}

export function loadRemembered(): RememberedPage[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(REMEMBERED_KEY) || "[]");
    return Array.isArray(parsed)
      ? parsed.filter(
          (p) => typeof p?.path === "string" && typeof p?.key === "string",
        )
      : [];
  } catch {
    return [];
  }
}

export function saveRemembered(list: RememberedPage[]): void {
  try {
    localStorage.setItem(REMEMBERED_KEY, JSON.stringify(list));
  } catch {
    // storage full or blocked — remembering silently no-ops
  }
}

export function rememberPage(path: string, keyPair: SignKeyPair): void {
  const list = loadRemembered().filter((p) => p.path !== path);
  list.push({ path, key: toBase64(keyPair.secretKey) });
  saveRemembered(list);
}

export function forgetPage(path: string): void {
  saveRemembered(loadRemembered().filter((p) => p.path !== path));
}

export function rememberedKeyPair(path: string): SignKeyPair | null {
  const entry = loadRemembered().find((p) => p.path === path);
  if (!entry) return null;
  try {
    return sign.keyPair.fromSecretKey(fromBase64(entry.key));
  } catch {
    return null;
  }
}

// The featured "main address" (which custom domain, if any, drives the QR code,
// printables, signature and heading) is a per-page preference kept on this
// device so it survives reloads.
export const MAIN_ADDRESS_KEY = "found.as:mainAddress";

export function loadMainAddress(path: string): string | null {
  if (!path) return null;
  try {
    const map = JSON.parse(localStorage.getItem(MAIN_ADDRESS_KEY) || "{}");
    const v = map?.[path];
    return typeof v === "string" && v ? v : null;
  } catch {
    return null;
  }
}

export function saveMainAddress(path: string, domain: string | null): void {
  if (!path) return;
  try {
    const map =
      JSON.parse(localStorage.getItem(MAIN_ADDRESS_KEY) || "{}") || {};
    if (domain) {
      map[path] = domain;
    } else {
      delete map[path];
    }
    localStorage.setItem(MAIN_ADDRESS_KEY, JSON.stringify(map));
  } catch {
    // storage blocked — the choice just won't persist across reloads
  }
}
