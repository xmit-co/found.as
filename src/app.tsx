import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { Signal, useSignal } from "@preact/signals";
import { marked } from "marked";
import fm from "front-matter";
import { sign, SignKeyPair } from "tweetnacl";
import { decode, encode } from "cbor-x";
import qrcode from "qrcode-generator";

const subtle = window.crypto.subtle;
const textEncoder = new TextEncoder();

enum Type {
  HTML_PAGE,
  MARKDOWN_PAGE,
  REDIR,
  BYTES,
  LINK_TREE,
}

type BuilderMode = "contact" | "advanced";

type LinkKind =
  | "phone"
  | "whatsapp"
  | "email"
  | "instagram"
  | "website"
  | "tiktok"
  | "youtube"
  | "linkedin"
  | "x"
  | "facebook"
  | "telegram"
  | "signal"
  | "matrix"
  | "github"
  | "mastodon"
  | "bluesky"
  | "threads"
  | "reddit"
  | "twitch"
  | "spotify"
  | "discord"
  | "snapchat"
  | "pinterest"
  | "substack"
  | "medium"
  | "patreon"
  | "calendly"
  | "paypal"
  | "venmo"
  | "cashapp"
  | "address"
  | "custom"
  | "section";

interface LinkItem {
  id: string;
  kind: LinkKind;
  label: string;
  value: string;
  href: string;
  enabled: boolean;
  featured?: boolean;
  icon?: string;
  relMe?: boolean;
}

interface SocialPreview {
  title?: string;
  description?: string;
  imageUrl?: string;
  autoImage?: boolean;
}

interface LinkTree {
  displayName: string;
  bio: string;
  avatarUrl?: string;
  theme: "system" | "light" | "dark" | "warm" | "clean";
  accent?: string;
  social?: SocialPreview;
  showVcard?: boolean;
  links: LinkItem[];
}

interface Private {
  type: Type;
  md: string;
  html: string;
  redir: string;
  linkTree?: LinkTree;
}

interface Public {
  redir?: string;
  html?: string;
  mime?: string;
  bytes?: Uint8Array;
  subs?: Record<string, { mime: string; bytes: Uint8Array }>;
}

interface NormalizedLink {
  item: LinkItem;
  label: string;
  href: string;
  warning?: string;
  error?: string;
}

interface CompressedAvatar {
  dataUrl: string;
  mime: "image/avif" | "image/jpeg";
  size: number;
}

class FourOFour extends Error {
  constructor(message: string) {
    super(message);
  }
}

class FourXX extends Error {
  constructor(message: string) {
    super(message);
  }
}

const recommendedKinds: LinkKind[] = ["phone", "email", "website", "custom"];

const additionalKinds: LinkKind[] = [
  "whatsapp",
  "instagram",
  "tiktok",
  "youtube",
  "linkedin",
  "x",
  "facebook",
  "telegram",
  "signal",
  "github",
  "mastodon",
  "bluesky",
  "threads",
  "reddit",
  "twitch",
  "spotify",
  "discord",
  "snapchat",
  "pinterest",
  "substack",
  "medium",
  "patreon",
  "calendly",
  "paypal",
  "venmo",
  "cashapp",
  "matrix",
  "address",
];

const kindLabels: Record<LinkKind, string> = {
  phone: "Phone",
  whatsapp: "WhatsApp",
  email: "Email",
  instagram: "Instagram",
  website: "Website",
  tiktok: "TikTok",
  youtube: "YouTube",
  linkedin: "LinkedIn",
  x: "X / Twitter",
  facebook: "Facebook",
  telegram: "Telegram",
  signal: "Signal",
  matrix: "Matrix",
  github: "GitHub",
  mastodon: "Mastodon",
  bluesky: "Bluesky",
  threads: "Threads",
  reddit: "Reddit",
  twitch: "Twitch",
  spotify: "Spotify",
  discord: "Discord",
  snapchat: "Snapchat",
  pinterest: "Pinterest",
  substack: "Substack",
  medium: "Medium",
  patreon: "Patreon",
  calendly: "Calendly",
  paypal: "PayPal",
  venmo: "Venmo",
  cashapp: "Cash App",
  address: "Address",
  custom: "Custom link",
  section: "Section header",
};

const kindExamples: Record<LinkKind, string> = {
  phone: "+33 6 12 34 56 78",
  whatsapp: "+33 6 12 34 56 78",
  email: "hello@example.com",
  instagram: "@found",
  website: "example.com",
  tiktok: "@found",
  youtube: "youtube.com/@found",
  linkedin: "linkedin.com/in/found",
  x: "@found",
  facebook: "facebook.com/found",
  telegram: "@found",
  signal: "signal.me/#eu/...",
  matrix: "@you:server.org",
  github: "found",
  mastodon: "@you@mastodon.social",
  bluesky: "you.bsky.social",
  threads: "@found",
  reddit: "found",
  twitch: "found",
  spotify: "found",
  discord: "discord.gg/found",
  snapchat: "@found",
  pinterest: "@found",
  substack: "found.substack.com",
  medium: "@found",
  patreon: "patreon.com/found",
  calendly: "calendly.com/found",
  paypal: "paypal.me/found",
  venmo: "found",
  cashapp: "$found",
  address: "1 Rue de Rivoli, Paris",
  custom: "https://example.com",
  section: "Work",
};

const kindDefaultValues: Record<LinkKind, string> = {
  phone: "",
  whatsapp: "",
  email: "",
  instagram: "https://instagram.com/",
  website: "https://",
  tiktok: "https://www.tiktok.com/@",
  youtube: "https://youtube.com/@",
  linkedin: "https://linkedin.com/in/",
  x: "https://x.com/",
  facebook: "https://facebook.com/",
  telegram: "https://t.me/",
  signal: "https://signal.me/#",
  matrix: "",
  github: "https://github.com/",
  mastodon: "",
  bluesky: "https://bsky.app/profile/",
  threads: "https://www.threads.net/@",
  reddit: "https://www.reddit.com/user/",
  twitch: "https://www.twitch.tv/",
  spotify: "https://open.spotify.com/user/",
  discord: "https://discord.gg/",
  snapchat: "https://www.snapchat.com/add/",
  pinterest: "https://www.pinterest.com/",
  substack: "",
  medium: "https://medium.com/@",
  patreon: "https://www.patreon.com/",
  calendly: "https://calendly.com/",
  paypal: "https://paypal.me/",
  venmo: "https://venmo.com/u/",
  cashapp: "https://cash.app/$",
  address: "",
  custom: "https://",
  section: "",
};

const kindDefaultIcons: Partial<Record<LinkKind, string>> = {
  phone: "📞",
  email: "✉️",
  website: "🌐",
  address: "📍",
  calendly: "📅",
  custom: "🔗",
};

// Kinds whose link points at something that is "also you" — a profile,
// address, or number — published with rel="me" identity metadata, which also
// lets Mastodon and other IndieWeb sites verify page ownership.
const identityKinds = new Set<LinkKind>([
  "email",
  "phone",
  "whatsapp",
  "signal",
  "website",
  "instagram",
  "tiktok",
  "youtube",
  "linkedin",
  "x",
  "facebook",
  "telegram",
  "matrix",
  "github",
  "mastodon",
  "bluesky",
  "threads",
  "reddit",
  "twitch",
  "spotify",
  "snapchat",
  "pinterest",
  "substack",
  "medium",
  "patreon",
]);

const kindIconSites: Partial<Record<LinkKind, string>> = {
  whatsapp: "https://www.whatsapp.com/",
  instagram: "https://www.instagram.com/",
  tiktok: "https://www.tiktok.com/",
  youtube: "https://www.youtube.com/",
  linkedin: "https://www.linkedin.com/",
  x: "https://x.com/",
  facebook: "https://www.facebook.com/",
  telegram: "https://telegram.org/",
  signal: "https://signal.org/",
  matrix: "https://matrix.org/",
  github: "https://github.com/",
  mastodon: "https://joinmastodon.org/",
  bluesky: "https://bsky.app/",
  threads: "https://www.threads.net/",
  reddit: "https://www.reddit.com/",
  twitch: "https://www.twitch.tv/",
  spotify: "https://open.spotify.com/",
  discord: "https://discord.com/",
  snapchat: "https://www.snapchat.com/",
  pinterest: "https://www.pinterest.com/",
  substack: "https://substack.com/",
  medium: "https://medium.com/",
  patreon: "https://www.patreon.com/",
  calendly: "https://calendly.com/",
  paypal: "https://www.paypal.com/",
  venmo: "https://venmo.com/",
  cashapp: "https://cash.app/",
};

function makeId(): string {
  if (window.crypto.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function isSection(item: LinkItem): boolean {
  return item.kind === "section";
}

function defaultLinkItem(kind: LinkKind): LinkItem {
  return {
    id: makeId(),
    kind,
    label: kind === "section" ? "" : kindLabels[kind],
    value: kindDefaultValues[kind],
    href: "",
    enabled: true,
    icon: kindDefaultIcons[kind],
  };
}

function createDefaultLinkTree(): LinkTree {
  return {
    displayName: "",
    bio: "",
    theme: "system",
    links: [],
  };
}

function createDefaultPrivate(): Private {
  return {
    type: Type.LINK_TREE,
    md: "",
    html: "",
    redir: "",
    linkTree: createDefaultLinkTree(),
  };
}

function ensureLinkTree(tree: LinkTree | undefined): LinkTree {
  const current = tree ?? createDefaultLinkTree();
  return {
    displayName: current.displayName ?? "",
    bio: current.bio ?? "",
    avatarUrl: current.avatarUrl ?? "",
    theme: current.theme ?? "system",
    accent: accentPair(current.accent) ? current.accent : "",
    social: {
      title: current.social?.title ?? "",
      description: current.social?.description ?? "",
      imageUrl: current.social?.imageUrl ?? "",
      autoImage: current.social?.autoImage ?? true,
    },
    showVcard: current.showVcard ?? true,
    links: current.links ?? [],
  };
}

function normalizePrivate(priv: Private): Private {
  if (priv.type === Type.LINK_TREE) {
    return {
      ...createDefaultPrivate(),
      ...priv,
      linkTree: ensureLinkTree(priv.linkTree),
    };
  }
  return {
    ...createDefaultPrivate(),
    ...priv,
  };
}

function normalizeUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) return trimmed;
  if (!trimmed.includes("://")) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function publicPageUrl(path: string): string {
  return `https://found.as/${encodePath(path)}`;
}

function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

function avatarImageSrc(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (/^data:image\/(avif|jpeg|jpg|png|webp);base64,/i.test(trimmed)) {
    return trimmed;
  }
  const normalized = normalizeUrl(trimmed);
  return URL.canParse(normalized) ? normalized : null;
}

// Accent choices are curated light/dark pairs rather than a free color picker:
// the accent doubles as text and borders on the page background, and the
// System theme flips that background with the OS. Each variant is tuned to
// WCAG AA both as text on its page background and under its button label
// (white on light variants, near-black on dark ones) — see palette.mjs.
interface AccentPair {
  light: string;
  dark: string;
}

const accentLightText = "#ffffff";
const accentDarkText = "#10130f";

const accentPalette: Record<string, AccentPair> = {
  ocean: { light: "#426ae0", dark: "#5177e8" },
  violet: { light: "#8e52d4", dark: "#9b61de" },
  magenta: { light: "#cf307f", dark: "#da418e" },
  crimson: { light: "#d72f3d", dark: "#e24451" },
  rust: { light: "#b6561e", dark: "#cd5c1b" },
  forest: { light: "#12814a", dark: "#14b866" },
  gold: { light: "#926a0c", dark: "#c28b0a" },
  graphite: { light: "#687480", dark: "#6c8093" },
};

function accentPair(value: string | undefined): AccentPair | null {
  return (value && accentPalette[value]) || null;
}

const themeAccentDefaults: Record<LinkTree["theme"], string> = {
  system: "#007f73",
  light: "#007f73",
  dark: "#4fc3b3",
  warm: "#9a4f24",
  clean: "#146c5d",
};

function socialImageUrl(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (!URL.canParse(trimmed)) return null;
  return new URL(trimmed).protocol === "https:" ? trimmed : null;
}

function signatureAvatarSrc(value: string | undefined): string | null {
  const src = avatarImageSrc(value);
  if (!src || !/^https:\/\//i.test(src)) return null;
  return src;
}

function signatureHtml(tree: LinkTree, url: string): string {
  const name = tree.displayName.trim();
  const bio = tree.bio.trim();
  const avatar = signatureAvatarSrc(tree.avatarUrl);
  const safeUrl = escapeHtml(url);
  const avatarCell = avatar
    ? `<td style="padding:0 14px 0 0;vertical-align:top;"><img src="${escapeHtml(avatar)}" alt="" width="56" height="56" style="display:block;width:56px;height:56px;border-radius:50%;"/></td>`
    : "";
  const nameLine = name
    ? `<div style="font-weight:bold;font-size:14px;line-height:1.4;color:#181818;">${escapeHtml(name)}</div>`
    : "";
  const bioLine = bio
    ? `<div style="font-size:12px;line-height:1.4;color:#595959;">${escapeHtml(bio)}</div>`
    : "";
  return `<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;font-family:Helvetica,Arial,sans-serif;"><tr>${avatarCell}<td style="vertical-align:top;">${nameLine}${bioLine}<div style="font-size:12px;line-height:1.6;"><a href="${safeUrl}" target="_blank" rel="noreferrer" style="color:#007f73;font-weight:bold;text-decoration:underline;">${safeUrl}</a></div></td></tr></table>`;
}

function signatureText(tree: LinkTree, url: string): string {
  return [tree.displayName.trim(), tree.bio.trim(), url]
    .filter(Boolean)
    .join("\n");
}

async function copyRichSignature(html: string, text: string): Promise<boolean> {
  if (
    navigator.clipboard &&
    "write" in navigator.clipboard &&
    typeof ClipboardItem !== "undefined"
  ) {
    try {
      await navigator.clipboard.write([
        new ClipboardItem({
          "text/html": new Blob([html], { type: "text/html" }),
          "text/plain": new Blob([text], { type: "text/plain" }),
        }),
      ]);
      return true;
    } catch {
      // Fall through to plain-text copy below.
    }
  }
  await navigator.clipboard.writeText(text);
  return false;
}

function canvasToBlob(
  canvas: HTMLCanvasElement,
  mime: CompressedAvatar["mime"],
  quality: number,
): Promise<Blob | null> {
  return new Promise((resolve) => {
    canvas.toBlob(resolve, mime, quality);
  });
}

function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(String(reader.result)));
    reader.addEventListener("error", () => reject(reader.error));
    reader.readAsDataURL(blob);
  });
}

async function loadImageForCanvas(file: File): Promise<CanvasImageSource> {
  if ("createImageBitmap" in window) {
    try {
      return await createImageBitmap(file, { imageOrientation: "from-image" });
    } catch {
      // Fall through to HTMLImageElement decoding below.
    }
  }

  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.decoding = "async";
    image.src = url;
    await image.decode();
    return image;
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function compressAvatar(file: File): Promise<CompressedAvatar> {
  const image = await loadImageForCanvas(file);
  const sourceWidth = Number("width" in image ? image.width : 0);
  const sourceHeight = Number("height" in image ? image.height : 0);
  if (!sourceWidth || !sourceHeight) {
    throw new Error("Could not read that image.");
  }

  const size = 320;
  const sourceSize = Math.min(sourceWidth, sourceHeight);
  const sourceX = Math.floor((sourceWidth - sourceSize) / 2);
  const sourceY = Math.floor((sourceHeight - sourceSize) / 2);
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error("Could not prepare the avatar image.");
  }
  ctx.drawImage(
    image,
    sourceX,
    sourceY,
    sourceSize,
    sourceSize,
    0,
    0,
    size,
    size,
  );
  if (image instanceof ImageBitmap) {
    image.close();
  }

  const attempts: { mime: CompressedAvatar["mime"]; quality: number }[] = [
    { mime: "image/avif", quality: 0.76 },
    { mime: "image/avif", quality: 0.64 },
    { mime: "image/jpeg", quality: 0.82 },
    { mime: "image/jpeg", quality: 0.72 },
  ];

  for (const attempt of attempts) {
    const blob = await canvasToBlob(canvas, attempt.mime, attempt.quality);
    if (blob?.type === attempt.mime) {
      return {
        dataUrl: await blobToDataUrl(blob),
        mime: attempt.mime,
        size: blob.size,
      };
    }
  }

  throw new Error("Could not compress that image.");
}

const linkIconPattern = /^data:image\/[a-z0-9.+-]+;base64,[a-z0-9+/=]+$/i;
const linkIconMaxRawBytes = 16 * 1024;

function linkIconSrc(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed && linkIconPattern.test(trimmed) ? trimmed : null;
}

function splitGraphemes(value: string): string[] {
  if (typeof Intl !== "undefined" && Intl.Segmenter) {
    return [
      ...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(
        value,
      ),
    ].map((part) => part.segment);
  }
  return [...value];
}

function linkIconEmoji(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed || trimmed.length > 16 || trimmed.startsWith("data:")) {
    return null;
  }
  return splitGraphemes(trimmed).length === 1 ? trimmed : null;
}

function canImportLinkIcon(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

async function reencodeLinkIcon(blob: Blob): Promise<string> {
  const image = await loadImageForCanvas(
    new File([blob], "icon", { type: blob.type }),
  );
  const sourceWidth = Number("width" in image ? image.width : 0);
  const sourceHeight = Number("height" in image ? image.height : 0);
  if (!sourceWidth || !sourceHeight) {
    throw new Error("Could not read that icon.");
  }
  const scale = Math.min(1, 64 / Math.max(sourceWidth, sourceHeight));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(sourceWidth * scale));
  canvas.height = Math.max(1, Math.round(sourceHeight * scale));
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error("Could not prepare the icon.");
  }
  ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
  if (image instanceof ImageBitmap) {
    image.close();
  }
  const png = await new Promise<Blob | null>((resolve) => {
    canvas.toBlob(resolve, "image/png");
  });
  if (!png) {
    throw new Error("Could not prepare the icon.");
  }
  return blobToDataUrl(png);
}

async function importLinkIcon(href: string): Promise<string> {
  const response = await fetch(
    `https://cc.me/icon?url=${encodeURIComponent(href)}`,
  );
  if (response.status === 404) {
    throw new Error("No icon found for that site.");
  }
  if (!response.ok) {
    throw new Error(`Icon lookup failed (${response.status}).`);
  }
  const blob = await response.blob();
  if (!blob.type.startsWith("image/")) {
    throw new Error("That site did not return an icon.");
  }
  if (blob.type === "image/svg+xml") {
    if (blob.size > linkIconMaxRawBytes) {
      throw new Error("That icon is too large.");
    }
    return blobToDataUrl(blob);
  }
  try {
    return await reencodeLinkIcon(blob);
  } catch {
    if (blob.size <= linkIconMaxRawBytes) {
      return blobToDataUrl(blob);
    }
    throw new Error("Could not read that icon.");
  }
}

function intoDoc(fragment: string, attrs: Record<string, any>) {
  const title = attrs["title"]
    ? `<title>${escapeHtml(String(attrs["title"]))}</title>`
    : "";
  return `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<style>
:root {
  color-scheme: light dark;
  background: Canvas;
  color: CanvasText;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
body {
  margin: 1rem;
  background: Canvas;
  color: CanvasText;
}
a {
  color: LinkText;
}
</style>
${title}
</head>
<body>${fragment}</body>
</html>`;
}

function normalizeSocialUsername(value: string): string {
  return value.trim().replace(/^@+/, "").replace(/^\/+/, "").split("?")[0];
}

function valueFromKnownHost(value: string, hosts: string[]): string | null {
  const normalized = normalizeUrl(value);
  if (!URL.canParse(normalized)) {
    return null;
  }
  const url = new URL(normalized);
  if (
    !hosts.some(
      (host) => url.hostname === host || url.hostname.endsWith(`.${host}`),
    )
  ) {
    return null;
  }
  const firstPart = url.pathname.split("/").filter(Boolean)[0];
  return firstPart ? decodeURIComponent(firstPart) : null;
}

function normalizePhone(value: string): Omit<NormalizedLink, "item" | "label"> {
  const cleaned = value.trim().replace(/[^\d+]/g, "");
  const digits = cleaned.replace(/\D/g, "");
  if (!digits) {
    return { href: "", error: "Enter a phone number." };
  }
  return {
    href: `tel:${cleaned}`,
    warning: cleaned.startsWith("+")
      ? undefined
      : "Add a country code if people may call from another country.",
  };
}

function normalizeWhatsApp(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const digits = value.trim().replace(/\D/g, "");
  if (!digits) {
    return { href: "", error: "Enter a WhatsApp phone number." };
  }
  return {
    href: `https://wa.me/${digits}`,
    warning: value.trim().startsWith("+")
      ? undefined
      : "WhatsApp works best with a country code.",
  };
}

function normalizeEmail(value: string): Omit<NormalizedLink, "item" | "label"> {
  const address = value.trim().replace(/^mailto:/i, "");
  if (!address) {
    return { href: "", error: "Enter an email address." };
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
    return { href: "", error: "Enter a valid email address." };
  }
  return { href: `mailto:${encodeURI(address)}` };
}

function normalizeInstagram(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (
    /^https?:\/\/(www\.)?instagram\.com\/?$/i.test(trimmed) ||
    trimmed === "@"
  ) {
    return { href: "", error: "Finish the Instagram link or username." };
  }
  const username =
    valueFromKnownHost(value, ["instagram.com"]) ??
    normalizeSocialUsername(value);
  if (!username) {
    return { href: "", error: "Enter an Instagram username or link." };
  }
  return { href: `https://www.instagram.com/${encodeURIComponent(username)}` };
}

function normalizeUsernameUrl(
  value: string,
  baseUrl: string,
  service: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed || trimmed === baseUrl) {
    return { href: "", error: `Enter a ${service} username or link.` };
  }
  if (trimmed.includes(".") || trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    if (!URL.canParse(normalized)) {
      return { href: "", error: `Enter a valid ${service} link.` };
    }
    return { href: normalized };
  }
  const username = normalizeSocialUsername(trimmed);
  if (!username) {
    return { href: "", error: `Enter a ${service} username.` };
  }
  return { href: `${baseUrl}${encodeURIComponent(username)}` };
}

function normalizeBluesky(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "https://bsky.app/profile/") {
    return { href: "", error: "Enter a Bluesky handle or link." };
  }
  if (trimmed.includes("://")) {
    return URL.canParse(trimmed)
      ? { href: trimmed }
      : { href: "", error: "Enter a valid Bluesky link." };
  }
  const handle = trimmed.replace(/^@+/, "");
  if (!handle) {
    return { href: "", error: "Enter a Bluesky handle." };
  }
  return { href: `https://bsky.app/profile/${encodeURIComponent(handle)}` };
}

function normalizeMastodon(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter a Mastodon address or link." };
  }
  if (trimmed.includes("://")) {
    return URL.canParse(trimmed)
      ? { href: trimmed }
      : { href: "", error: "Enter a valid Mastodon link." };
  }
  const [user, host] = trimmed.replace(/^@+/, "").split("@");
  if (user && host) {
    return { href: `https://${host}/@${encodeURIComponent(user)}` };
  }
  return {
    href: "",
    error: "Use @you@server, or paste your profile link.",
  };
}

function normalizeMatrix(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter a Matrix ID or link." };
  }
  if (trimmed.includes("://")) {
    return URL.canParse(trimmed)
      ? { href: trimmed }
      : { href: "", error: "Enter a valid Matrix link." };
  }
  const id = trimmed.replace(/^@+/, "");
  if (id.includes(":")) {
    return { href: `https://matrix.to/#/@${id}` };
  }
  return {
    href: "",
    error: "Use @you:server.org, or paste a matrix.to link.",
  };
}

function normalizeSubstack(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter a Substack name or link." };
  }
  if (trimmed.includes(".") || trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    if (!URL.canParse(normalized)) {
      return { href: "", error: "Enter a valid Substack link." };
    }
    return { href: normalized };
  }
  const name = normalizeSocialUsername(trimmed);
  if (!name || !/^[a-z0-9-]+$/i.test(name)) {
    return { href: "", error: "Enter a Substack name or link." };
  }
  return { href: `https://${name.toLowerCase()}.substack.com` };
}

function normalizeCashApp(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "https://cash.app/$") {
    return { href: "", error: "Enter a Cash App cashtag or link." };
  }
  if (trimmed.includes(".") || trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    if (!URL.canParse(normalized)) {
      return { href: "", error: "Enter a valid Cash App link." };
    }
    return { href: normalized };
  }
  const tag = trimmed.replace(/^\$+/, "");
  if (!tag) {
    return { href: "", error: "Enter a Cash App cashtag." };
  }
  return { href: `https://cash.app/$${encodeURIComponent(tag)}` };
}

function normalizeMap(value: string): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter an address or map link." };
  }
  if (trimmed.includes("://")) {
    if (!URL.canParse(trimmed)) {
      return { href: "", error: "Enter a valid map link." };
    }
    return { href: trimmed };
  }
  return {
    href: `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(trimmed)}`,
  };
}

function normalizeGenericLink(
  value: string,
  label: string,
  incompleteValue = "",
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  const unfinished = incompleteValue.trim();
  if (
    unfinished &&
    trimmed.replace(/\/$/, "") === unfinished.replace(/\/$/, "")
  ) {
    return { href: "", error: `Finish the ${label.toLowerCase()} link.` };
  }
  const normalized = normalizeUrl(value);
  if (!normalized) {
    return { href: "", error: `Enter a ${label.toLowerCase()} link.` };
  }
  if (!URL.canParse(normalized)) {
    return { href: "", error: `Enter a valid ${label.toLowerCase()} link.` };
  }
  return { href: normalized };
}

function normalizeByKind(
  kind: LinkKind,
  value: string,
  label: string,
): Omit<NormalizedLink, "item" | "label"> {
  switch (kind) {
    case "phone":
      return normalizePhone(value);
    case "whatsapp":
      return normalizeWhatsApp(value);
    case "email":
      return normalizeEmail(value);
    case "instagram":
      return normalizeInstagram(value);
    case "tiktok":
      return normalizeUsernameUrl(value, "https://www.tiktok.com/@", "TikTok");
    case "x":
      return normalizeUsernameUrl(value, "https://x.com/", "X / Twitter");
    case "telegram":
      return normalizeUsernameUrl(value, "https://t.me/", "Telegram");
    case "github":
      return normalizeUsernameUrl(value, "https://github.com/", "GitHub");
    case "reddit":
      return normalizeUsernameUrl(
        value,
        "https://www.reddit.com/user/",
        "Reddit",
      );
    case "twitch":
      return normalizeUsernameUrl(value, "https://www.twitch.tv/", "Twitch");
    case "spotify":
      return normalizeUsernameUrl(
        value,
        "https://open.spotify.com/user/",
        "Spotify",
      );
    case "threads":
      return normalizeUsernameUrl(
        value,
        "https://www.threads.net/@",
        "Threads",
      );
    case "discord":
      return normalizeUsernameUrl(value, "https://discord.gg/", "Discord");
    case "snapchat":
      return normalizeUsernameUrl(
        value,
        "https://www.snapchat.com/add/",
        "Snapchat",
      );
    case "pinterest":
      return normalizeUsernameUrl(
        value,
        "https://www.pinterest.com/",
        "Pinterest",
      );
    case "medium":
      return normalizeUsernameUrl(value, "https://medium.com/@", "Medium");
    case "patreon":
      return normalizeUsernameUrl(value, "https://www.patreon.com/", "Patreon");
    case "calendly":
      return normalizeUsernameUrl(value, "https://calendly.com/", "Calendly");
    case "paypal":
      return normalizeUsernameUrl(value, "https://paypal.me/", "PayPal");
    case "venmo":
      return normalizeUsernameUrl(value, "https://venmo.com/u/", "Venmo");
    case "substack":
      return normalizeSubstack(value);
    case "cashapp":
      return normalizeCashApp(value);
    case "bluesky":
      return normalizeBluesky(value);
    case "mastodon":
      return normalizeMastodon(value);
    case "matrix":
      return normalizeMatrix(value);
    case "address":
      return normalizeMap(value);
    default:
      return normalizeGenericLink(value, label, kindDefaultValues[kind]);
  }
}

function isAllowedHref(href: string): boolean {
  if (!URL.canParse(href)) return false;
  const protocol = new URL(href).protocol;
  return (
    protocol === "https:" ||
    protocol === "http:" ||
    protocol === "mailto:" ||
    protocol === "tel:"
  );
}

function normalizeLink(item: LinkItem): NormalizedLink {
  const label = item.label.trim() || kindLabels[item.kind];
  if (item.kind === "section") {
    return { item, label, href: "" };
  }
  const value = item.value.trim();
  if (!item.enabled || !value) {
    return { item, label, href: "" };
  }

  const normalized = normalizeByKind(item.kind, value, label);
  if (normalized.href && !isAllowedHref(normalized.href)) {
    return {
      item,
      label,
      href: "",
      error: `Enter an https:// ${label} link.`,
    };
  }
  return { item, label, ...normalized };
}

function normalizedLinks(tree: LinkTree): NormalizedLink[] {
  return tree.links.map(normalizeLink);
}

function shownSectionIds(tree: LinkTree): Set<string> {
  const ids = new Set<string>();
  for (const entry of linkTreeListedEntries(tree)) {
    if (entry.kind === "section") {
      ids.add(entry.id);
    }
  }
  return ids;
}

function isDefaultLinkValue(link: LinkItem): boolean {
  const value = link.value.trim().replace(/\/$/, "");
  const defaultValue = kindDefaultValues[link.kind].trim().replace(/\/$/, "");
  return Boolean(defaultValue) && value === defaultValue;
}

function activeValidLinks(tree: LinkTree): NormalizedLink[] {
  return normalizedLinks(tree).filter((link) => link.href && !link.error);
}

function canFeature(link: LinkItem): boolean {
  return !isSection(link);
}

type RenderEntry =
  | { kind: "section"; title: string; id: string }
  | { kind: "link"; link: NormalizedLink };

function linkTreeRenderEntries(tree: LinkTree): RenderEntry[] {
  const entries: RenderEntry[] = [];
  for (const normalized of normalizedLinks(tree)) {
    if (isSection(normalized.item)) {
      const title = normalized.item.label.trim();
      if (normalized.item.enabled && title) {
        entries.push({ kind: "section", title, id: normalized.item.id });
      }
      continue;
    }
    if (normalized.href && !normalized.error) {
      entries.push({ kind: "link", link: normalized });
    }
  }
  return entries.filter(
    (entry, index) =>
      entry.kind !== "section" || entries[index + 1]?.kind === "link",
  );
}

function featuredLink(tree: LinkTree): NormalizedLink | undefined {
  return activeValidLinks(tree).find(
    (link) => link.item.featured && canFeature(link.item),
  );
}

function linkTreeListedEntries(tree: LinkTree): RenderEntry[] {
  const featured = featuredLink(tree);
  const listed = featured
    ? linkTreeRenderEntries(tree).filter(
        (entry) => entry.kind !== "link" || entry.link.item !== featured.item,
      )
    : linkTreeRenderEntries(tree);
  return listed.filter(
    (entry, index) =>
      entry.kind !== "section" || listed[index + 1]?.kind === "link",
  );
}

function linkTreeHasPublishableContent(tree: LinkTree): boolean {
  return Boolean(
    tree.displayName.trim() ||
    tree.bio.trim() ||
    avatarImageSrc(tree.avatarUrl) ||
    activeValidLinks(tree).length,
  );
}

function linkTreeErrors(tree: LinkTree): string[] {
  const errors = normalizedLinks(tree)
    .filter(
      (link) =>
        link.error &&
        link.item.enabled &&
        link.item.value.trim() &&
        !isDefaultLinkValue(link.item),
    )
    .map((link) => `${link.label}: ${link.error}`);
  if (tree.social?.imageUrl?.trim() && !socialImageUrl(tree.social.imageUrl)) {
    errors.push(
      "Social preview image: enter a full https:// image address, or leave it blank.",
    );
  }
  return errors;
}

function escapeVcardValue(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r\n|\r|\n/g, "\\n");
}

function vcardUriValue(value: string): string {
  return value.replace(/[\r\n]/g, "");
}

function utf8Octets(codePoint: number): number {
  if (codePoint < 0x80) return 1;
  if (codePoint < 0x800) return 2;
  if (codePoint < 0x10000) return 3;
  return 4;
}

function foldVcardLine(line: string): string {
  const parts: string[] = [];
  let current = "";
  let octets = 0;
  for (const char of line) {
    const size = utf8Octets(char.codePointAt(0)!);
    if (octets + size > 75) {
      parts.push(current);
      current = " ";
      octets = 1;
    }
    current += char;
    octets += size;
  }
  if (current) parts.push(current);
  return parts.join("\r\n");
}

function vcardNameLine(displayName: string): string {
  const parts = displayName.trim().split(/\s+/);
  const family = parts.length > 1 ? parts[parts.length - 1] : "";
  const given = parts.length > 1 ? parts.slice(0, -1).join(" ") : parts[0];
  return `N:${escapeVcardValue(family)};${escapeVcardValue(given)};;;`;
}

function vcardPhotoLine(avatarUrl: string | undefined): string | null {
  const src = avatarImageSrc(avatarUrl);
  if (!src) return null;
  const embedded = src.match(
    /^data:image\/(jpeg|jpg|png);base64,([A-Za-z0-9+/=]+)$/i,
  );
  if (embedded) {
    const type = embedded[1].toLowerCase() === "png" ? "PNG" : "JPEG";
    return `PHOTO;ENCODING=b;TYPE=${type}:${embedded[2]}`;
  }
  if (/^https?:\/\//i.test(src)) {
    return `PHOTO;VALUE=URI:${vcardUriValue(src)}`;
  }
  return null;
}

function vcardFileName(displayName: string): string {
  const base = displayName
    .trim()
    .replace(/[\\/:*?"<>|]+/g, "")
    .trim();
  return `${base || "contact"}.vcf`;
}

function vcardEligible(tree: LinkTree): boolean {
  return (
    Boolean(tree.displayName.trim()) &&
    activeValidLinks(tree).some(
      (link) =>
        link.item.kind === "phone" ||
        link.item.kind === "whatsapp" ||
        link.item.kind === "email",
    )
  );
}

function buildVcard(
  tree: LinkTree,
  pageUrl: string,
  includePhoto = true,
): string | null {
  const name = tree.displayName.trim();
  if (!name) return null;
  const tels: string[] = [];
  const emails: string[] = [];
  const urls: string[] = [];
  const addresses: string[] = [];
  for (const link of activeValidLinks(tree)) {
    const kind = link.item.kind;
    const value = link.item.value.trim();
    if (kind === "phone" || kind === "whatsapp") {
      const cleaned = value.replace(/[^\d+]/g, "");
      if (cleaned && !tels.includes(cleaned)) tels.push(cleaned);
    } else if (kind === "email") {
      const address = value.replace(/^mailto:/i, "");
      if (address && !emails.includes(address)) emails.push(address);
    } else if (kind === "website" || kind === "custom") {
      if (!urls.includes(link.href)) urls.push(link.href);
    } else if (kind === "address") {
      if (value.includes("://")) {
        if (!urls.includes(link.href)) urls.push(link.href);
      } else if (!addresses.includes(value)) {
        addresses.push(value);
      }
    }
  }
  if (!tels.length && !emails.length) return null;
  const bio = tree.bio.trim();
  const photo = includePhoto ? vcardPhotoLine(tree.avatarUrl) : null;
  const lines = [
    "BEGIN:VCARD",
    "VERSION:3.0",
    `FN:${escapeVcardValue(name)}`,
    vcardNameLine(name),
    ...(bio ? [`NOTE:${escapeVcardValue(bio)}`] : []),
    ...tels.map((tel) => `TEL;TYPE=CELL:${escapeVcardValue(tel)}`),
    ...emails.map((email) => `EMAIL;TYPE=INTERNET:${escapeVcardValue(email)}`),
    ...urls.map((url) => `URL:${vcardUriValue(url)}`),
    ...(pageUrl ? [`URL:${vcardUriValue(pageUrl)}`] : []),
    ...addresses.map((adr) => `ADR;TYPE=HOME:;;${escapeVcardValue(adr)};;;;`),
    ...(photo ? [photo] : []),
    "END:VCARD",
  ];
  return lines.map(foldVcardLine).join("\r\n");
}

interface OgColors {
  bg: string;
  text: string;
  muted: string;
  accent: string;
  accentText: string;
}

// og:image renders one fixed look per theme; System renders as light.
function ogColors(tree: LinkTree): OgColors {
  const pair = accentPair(tree.accent);
  if (tree.theme === "dark") {
    return {
      bg: "#101112",
      text: "#f5f5f0",
      muted: "#c1c1ba",
      accent: pair?.dark ?? "#4fc3b3",
      accentText: pair ? accentDarkText : "#07100f",
    };
  }
  const defaults: Record<string, { bg: string; accent: string }> = {
    warm: { bg: "#fbf8f0", accent: "#9a4f24" },
    clean: { bg: "#f7faf8", accent: "#146c5d" },
  };
  const d = defaults[tree.theme] ?? { bg: "#fbfbf8", accent: "#007f73" };
  return {
    bg: d.bg,
    text: "#181818",
    muted: "#595959",
    accent: pair?.light ?? d.accent,
    accentText: pair ? accentLightText : "#ffffff",
  };
}

function wrapCanvasText(
  ctx: CanvasRenderingContext2D,
  text: string,
  maxWidth: number,
  maxLines: number,
): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (ctx.measureText(candidate).width <= maxWidth) {
      line = candidate;
      continue;
    }
    if (line) lines.push(line);
    line = word;
    if (lines.length > maxLines) break;
  }
  if (line) lines.push(line);
  if (lines.length > maxLines) {
    lines.length = maxLines;
    lines[maxLines - 1] += "…";
  }
  return lines;
}

async function renderOgImage(
  tree: LinkTree,
  display: string,
): Promise<Uint8Array | null> {
  const canvas = document.createElement("canvas");
  canvas.width = 1200;
  canvas.height = 630;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  const colors = ogColors(tree);
  const name = tree.displayName.trim() || display;
  const bio = tree.bio.trim();
  const font = (weight: number, size: number) =>
    `${weight} ${size}px ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif`;

  ctx.fillStyle = colors.bg;
  ctx.fillRect(0, 0, 1200, 630);

  // Only data: avatars are drawn — a remote avatar would taint the canvas.
  const avatarSrc = tree.avatarUrl?.trim().startsWith("data:")
    ? avatarImageSrc(tree.avatarUrl)
    : null;
  let nameY = 230;
  if (avatarSrc) {
    try {
      const img = await new Promise<HTMLImageElement>((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error("Could not read the photo."));
        image.src = avatarSrc;
      });
      ctx.save();
      ctx.beginPath();
      ctx.arc(600, 168, 90, 0, Math.PI * 2);
      ctx.clip();
      const scale = Math.max(180 / img.width, 180 / img.height);
      const w = img.width * scale;
      const h = img.height * scale;
      ctx.drawImage(img, 600 - w / 2, 168 - h / 2, w, h);
      ctx.restore();
      nameY = 330;
    } catch {
      // Render without the photo.
    }
  }

  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  let nameSize = 68;
  ctx.font = font(800, nameSize);
  while (ctx.measureText(name).width > 1040 && nameSize > 34) {
    nameSize -= 4;
    ctx.font = font(800, nameSize);
  }
  ctx.fillStyle = colors.text;
  ctx.fillText(name, 600, nameY);

  if (bio) {
    ctx.font = font(500, 34);
    ctx.fillStyle = colors.muted;
    const lines = wrapCanvasText(ctx, bio, 980, 2);
    lines.forEach((line, i) => ctx.fillText(line, 600, nameY + 66 + i * 46));
  }

  ctx.font = font(700, 32);
  const labelWidth = ctx.measureText(display).width;
  const pillWidth = labelWidth + 72;
  const pillHeight = 76;
  const pillY = 630 - pillHeight - 52;
  ctx.fillStyle = colors.accent;
  ctx.beginPath();
  ctx.roundRect(600 - pillWidth / 2, pillY, pillWidth, pillHeight, 38);
  ctx.fill();
  ctx.fillStyle = colors.accentText;
  ctx.fillText(display, 600, pillY + pillHeight / 2 + 2);

  const blob = await new Promise<Blob | null>((resolve) =>
    canvas.toBlob(resolve, "image/png"),
  );
  if (!blob) return null;
  return new Uint8Array(await blob.arrayBuffer());
}

function linkTreeToHtml(
  tree: LinkTree,
  url: string,
  generatedOgUrl?: string,
): string {
  const safeName = tree.displayName.trim() || "Contact";
  const safeBio = tree.bio.trim();
  const avatar = avatarImageSrc(tree.avatarUrl);
  const metaTitle = tree.social?.title?.trim() || safeName;
  const metaDescription =
    tree.social?.description?.trim() || safeBio || `${safeName} on found.as`;
  const ogImage = socialImageUrl(tree.social?.imageUrl) ?? generatedOgUrl;
  const featured = featuredLink(tree);
  const entries = linkTreeListedEntries(tree);
  const themeClass = `theme-${tree.theme || "system"}`;
  const accent = accentPair(tree.accent);
  const accentCss = !accent
    ? ""
    : tree.theme === "dark"
      ? `html.theme-dark {
  --accent: ${accent.dark};
  --accent-text: ${accentDarkText};
}
`
      : tree.theme === "system" || !tree.theme
        ? `html.theme-system {
  --accent: ${accent.light};
  --accent-text: ${accentLightText};
}
@media (prefers-color-scheme: dark) {
  html.theme-system {
    --accent: ${accent.dark};
    --accent-text: ${accentDarkText};
  }
}
`
        : `html.${themeClass} {
  --accent: ${accent.light};
  --accent-text: ${accentLightText};
}
`;
  const vcard = tree.showVcard !== false ? buildVcard(tree, url) : null;
  const vcardHref = vcard
    ? `data:text/vcard;charset=utf-8,${encodeURIComponent(vcard)}`
    : "";
  const linkIconHtml = (link: NormalizedLink) => {
    const icon = linkIconSrc(link.item.icon);
    if (icon) {
      return `<img class="link-icon" src="${escapeHtml(icon)}" alt="" width="20" height="20"/>`;
    }
    const emoji = linkIconEmoji(link.item.icon);
    return emoji
      ? `<span class="link-icon-emoji" aria-hidden="true">${escapeHtml(emoji)}</span>`
      : "";
  };
  const linkRelAttr = (link: NormalizedLink) =>
    identityKinds.has(link.item.kind) &&
    link.item.relMe !== false &&
    /^(https?:|mailto:|tel:|sms:)/i.test(link.href)
      ? ' rel="me"'
      : "";

  return `<!DOCTYPE html>
<html lang="en" class="${themeClass}">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<meta name="description" content="${escapeHtml(metaDescription)}"/>
<meta property="og:title" content="${escapeHtml(metaTitle)}"/>
<meta property="og:description" content="${escapeHtml(metaDescription)}"/>
<meta property="og:type" content="website"/>
<meta property="og:url" content="${escapeHtml(url)}"/>
${ogImage ? `<meta property="og:image" content="${escapeHtml(ogImage)}"/>\n` : ""}<meta name="twitter:card" content="${ogImage ? "summary_large_image" : "summary"}"/>
<title>${escapeHtml(metaTitle)}</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #fbfbf8;
  --text: #181818;
  --muted: #595959;
  --panel: #ffffff;
  --border: #d7d7d0;
  --accent: #007f73;
  --accent-text: #ffffff;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.theme-dark {
  color-scheme: dark;
  --bg: #101112;
  --text: #f5f5f0;
  --muted: #c1c1ba;
  --panel: #191b1d;
  --border: #33373a;
  --accent: #4fc3b3;
  --accent-text: #07100f;
}
.theme-light {
  color-scheme: light;
}
.theme-warm {
  color-scheme: light;
  --bg: #fbf8f0;
  --text: #221b13;
  --muted: #665b4c;
  --panel: #ffffff;
  --border: #ddd2c1;
  --accent: #9a4f24;
}
.theme-clean {
  color-scheme: light;
  --bg: #f7faf8;
  --text: #15201d;
  --muted: #52615c;
  --panel: #ffffff;
  --border: #cfddd8;
  --accent: #146c5d;
}
@media (prefers-color-scheme: dark) {
  .theme-system {
    --bg: #101112;
    --text: #f5f5f0;
    --muted: #c1c1ba;
    --panel: #191b1d;
    --border: #33373a;
    --accent: #4fc3b3;
    --accent-text: #07100f;
  }
}
${accentCss}* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100svh;
  display: grid;
  place-items: center;
  padding: 24px;
  background: var(--bg);
  color: var(--text);
}
main {
  width: min(100%, 440px);
}
.profile {
  text-align: center;
  margin-bottom: 24px;
}
.avatar {
  width: 88px;
  height: 88px;
  border-radius: 50%;
  border: 1px solid var(--border);
  background: var(--panel);
  display: inline-grid;
  place-items: center;
  margin-bottom: 16px;
  overflow: hidden;
  color: var(--accent);
  font-size: 28px;
  font-weight: 700;
}
.avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
h1 {
  margin: 0;
  font-size: clamp(2rem, 9vw, 3rem);
  line-height: 1;
  letter-spacing: 0;
}
p {
  margin: 12px 0 0;
  color: var(--muted);
  font-size: 1rem;
  line-height: 1.5;
}
nav {
  display: grid;
  gap: 10px;
}
a.contact-link {
  min-height: 48px;
  display: block;
  align-content: center;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
  color: var(--text);
  text-align: center;
  text-decoration: none;
  font-weight: 650;
}
a.contact-link:hover {
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 12%, var(--panel));
}
a.contact-link:focus-visible {
  border-color: var(--accent);
  outline: 3px solid color-mix(in srgb, var(--accent), transparent 70%);
  outline-offset: 2px;
}
a.vcard-button {
  min-height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 0 16px;
  padding: 10px 16px;
  border: 1px solid var(--accent);
  border-radius: 8px;
  background: transparent;
  color: var(--accent);
  text-decoration: none;
  font-weight: 650;
}
a.vcard-button:hover {
  background: color-mix(in srgb, var(--accent) 12%, var(--bg));
}
a.vcard-button:focus-visible {
  outline: 3px solid var(--text);
  outline-offset: 2px;
}
a.contact-link.featured {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--accent-text);
}
a.contact-link.featured:hover {
  border-color: color-mix(in srgb, var(--accent) 85%, var(--text));
  background: color-mix(in srgb, var(--accent) 85%, var(--text));
}
a.contact-link.featured:focus-visible {
  outline: 3px solid var(--text);
  outline-offset: 2px;
}
h2.link-section {
  margin: 14px 0 0;
  font-size: 0.82rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  text-align: center;
  color: var(--muted);
}
h2.link-section:first-child {
  margin-top: 0;
}
img.link-icon {
  width: 20px;
  height: 20px;
  border-radius: 4px;
  margin-right: 10px;
  vertical-align: -4px;
}
span.link-icon-emoji {
  margin-right: 10px;
}
</style>
</head>
<body>
<main>
  <section class="profile" aria-labelledby="profile-title">
    ${avatar ? `<div class="avatar" aria-hidden="true"><img src="${escapeHtml(avatar)}" alt=""/></div>` : ""}
    <h1 id="profile-title">${escapeHtml(safeName)}</h1>
    ${safeBio ? `<p>${escapeHtml(safeBio)}</p>` : ""}
  </section>
  ${
    vcard
      ? `<a class="vcard-button" href="${escapeHtml(vcardHref)}" download="${escapeHtml(vcardFileName(tree.displayName))}">Save contact</a>`
      : ""
  }
  ${
    featured || entries.length
      ? `<nav aria-label="Contact links">
    ${[
      ...(featured
        ? [
            `<a class="contact-link featured" href="${escapeHtml(featured.href)}"${linkRelAttr(featured)}>${linkIconHtml(featured)}${escapeHtml(featured.label)}</a>`,
          ]
        : []),
      ...entries.map((entry) =>
        entry.kind === "section"
          ? `<h2 class="link-section">${escapeHtml(entry.title)}</h2>`
          : `<a class="contact-link" href="${escapeHtml(entry.link.href)}"${linkRelAttr(entry.link)}>${linkIconHtml(entry.link)}${escapeHtml(entry.link.label)}</a>`,
      ),
    ].join("\n    ")}
  </nav>`
      : ""
  }
</main>
</body>
</html>`;
}

interface QrModel {
  dim: number;
  cells: { x: number; y: number }[];
}

function buildQrModel(value: string): QrModel {
  const margin = 2;
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();
  const count = qr.getModuleCount();
  const dim = count + margin * 2;
  const cells: { x: number; y: number }[] = [];
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) {
        cells.push({ x: col + margin, y: row + margin });
      }
    }
  }
  return { dim, cells };
}

function qrSvgString(value: string, size: string): string {
  const model = buildQrModel(value);
  const rects = model.cells
    .map((cell) => `<rect x="${cell.x}" y="${cell.y}" width="1" height="1"/>`)
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${model.dim} ${model.dim}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${model.dim}" height="${model.dim}" fill="#ffffff"/><g fill="#111111">${rects}</g></svg>`;
}

function downloadFile(filename: string, blob: Blob): void {
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

function recoveryKitHtml(path: string, pw: string, url: string): string {
  let qr = "";
  try {
    qr = qrSvgString(url, "128");
  } catch {
    // Without a QR the kit is still complete.
  }
  const editUrl = `https://be.found.as/${encodePath(path)}`;
  const date = new Date().toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Recovery kit — found.as/${escapeHtml(path)}</title>
<style>
body { margin: 0; padding: 40px 24px; font-family: ui-sans-serif, system-ui, sans-serif; color: #181818; background: #ffffff; line-height: 1.6; }
main { max-width: 560px; margin-inline: auto; }
h1 { font-size: 1.6rem; margin: 0 0 4px; }
.date { color: #595959; margin: 0 0 24px; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 0 0 24px; }
dt { font-weight: 700; }
dd { margin: 0; overflow-wrap: anywhere; }
code { padding: 2px 8px; border: 1px solid #d7d7d0; border-radius: 6px; background: #f6f6f2; font-size: 1.05em; }
.warning { padding: 12px 16px; border: 1px solid #d7d7d0; border-left: 4px solid #9a4f24; border-radius: 6px; background: #fbf8f0; }
.qr { margin-top: 24px; }
@media print { body { padding: 0; } }
</style>
</head>
<body>
<main>
<h1>👋 found.as recovery kit</h1>
<p class="date">Saved on ${escapeHtml(date)}</p>
<dl>
<dt>Your page</dt><dd><a href="${escapeHtml(url)}">${escapeHtml(url)}</a></dd>
<dt>Edit it at</dt><dd><a href="${escapeHtml(editUrl)}">${escapeHtml(editUrl)}</a></dd>
<dt>Password</dt><dd>${pw ? `<code>${escapeHtml(pw)}</code>` : "<em>blank — no password was set</em>"}</dd>
</dl>
<p class="warning"><strong>Keep this file private.</strong> Anyone who has it can edit your page. found.as has no password reset — if you forget your password, this file is the only way back in. Keep it in your password manager, or print it and keep it somewhere safe.</p>
<p class="qr">${qr}</p>
</main>
</body>
</html>`;
}

// Accents legible on white for print, per theme (the dark theme's on-screen
// accent is too pale for paper, so it borrows the system pair's light variant).
const printAccents: Record<LinkTree["theme"], string> = {
  system: "#007f73",
  light: "#007f73",
  dark: "#007f73",
  warm: "#9a4f24",
  clean: "#146c5d",
};

function printablesHtml(tree: LinkTree, url: string, display: string): string {
  const name = tree.displayName.trim() || display;
  const bio = tree.bio.trim();
  const accent = accentPair(tree.accent)?.light ?? printAccents[tree.theme];
  const avatar = avatarImageSrc(tree.avatarUrl);
  let cardQr = "";
  let posterQr = "";
  try {
    cardQr = qrSvgString(url, "26mm");
    posterQr = qrSvgString(url, "56mm");
  } catch {
    // Cards still work without a QR.
  }
  const card = `<div class="card">
  <div class="card-text">
    <p class="card-name">${escapeHtml(name)}</p>
    ${bio ? `<p class="card-bio">${escapeHtml(bio)}</p>` : ""}
    <p class="card-url">${escapeHtml(display)}</p>
  </div>
  ${cardQr}
</div>`;
  // Cut-line ticks at the sheet margins: rule a line between matching ticks
  // and cut edge to edge; no ink ends up on the cards themselves.
  const cutMarks = [
    ...[0, 85, 170].flatMap((x) => [
      `<i class="mark mark-v" style="left:${x}mm;top:-8mm"></i>`,
      `<i class="mark mark-v" style="left:${x}mm;bottom:-8mm"></i>`,
    ]),
    ...[0, 55, 110, 165, 220].flatMap((y) => [
      `<i class="mark mark-h" style="top:${y}mm;left:-8mm"></i>`,
      `<i class="mark mark-h" style="top:${y}mm;right:-8mm"></i>`,
    ]),
  ].join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Print — ${escapeHtml(display)}</title>
<style>
/* margin: 0 also removes the browser's default page headers and footers;
   the sheet carries its own padding so content clears printer margins. */
@page { margin: 0; }
* { box-sizing: border-box; }
body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; color: #181818; background: #ffffff; }
.toolbar { display: flex; align-items: center; justify-content: center; gap: 16px; padding: 12px 16px; border-bottom: 1px solid #d7d7d0; background: #f6f6f2; }
.toolbar p { margin: 0; color: #595959; }
.toolbar button { min-height: 40px; padding: 8px 20px; border: 0; border-radius: 8px; background: ${accent}; color: #ffffff; font-weight: 700; font-size: 1rem; cursor: pointer; }
.sheet { position: relative; width: 170mm; margin: 12mm auto; display: grid; grid-template-columns: repeat(2, 85mm); }
.card { width: 85mm; height: 55mm; display: flex; align-items: center; gap: 4mm; padding: 6mm; break-inside: avoid; }
.mark { position: absolute; }
.mark-v { width: 0; height: 6mm; border-left: 0.2mm solid #9a9a94; }
.mark-h { width: 6mm; height: 0; border-top: 0.2mm solid #9a9a94; }
.card svg { flex: none; }
.card-text { flex: 1; min-width: 0; }
.card-name { margin: 0; font-size: 12pt; font-weight: 800; line-height: 1.25; }
.card-bio { margin: 1mm 0 0; color: #595959; font-size: 8pt; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
.card-url { margin: 2mm 0 0; color: ${accent}; font-size: 9pt; font-weight: 700; overflow-wrap: anywhere; }
.poster { break-before: page; min-height: 250mm; display: grid; place-content: center; justify-items: center; gap: 5mm; text-align: center; padding: 14mm 10mm; }
.poster-avatar { width: 30mm; height: 30mm; border-radius: 50%; object-fit: cover; margin-bottom: 2mm; }
.poster-name { margin: 0; font-size: 24pt; font-weight: 800; }
.poster-bio { margin: 0; max-width: 120mm; color: #595959; font-size: 12pt; }
.poster-cta { margin: 8mm 0 1mm; color: ${accent}; font-size: 10pt; font-weight: 800; letter-spacing: 0.14em; text-transform: uppercase; }
.poster-url { margin: 0; font-size: 13pt; font-weight: 700; color: ${accent}; }
@media print { .toolbar { display: none; } .sheet { padding: 0; } }
</style>
</head>
<body>
<header class="toolbar">
<p>Business cards — cut straight lines between the edge marks. Poster on the second page. Print at 100% scale.</p>
<button type="button" onclick="print()">Print</button>
</header>
<section class="sheet" aria-label="Business cards">
${cutMarks}
${Array.from({ length: 8 }, () => card).join("\n")}
</section>
<section class="poster" aria-label="Poster">
${avatar ? `<img class="poster-avatar" src="${escapeHtml(avatar)}" alt=""/>` : ""}
<h1 class="poster-name">${escapeHtml(name)}</h1>
${bio ? `<p class="poster-bio">${escapeHtml(bio)}</p>` : ""}
<p class="poster-cta">Scan to reach me</p>
${posterQr}
<p class="poster-url">${escapeHtml(display)}</p>
</section>
</body>
</html>`;
}

function downloadQrPng(value: string, filename: string): void {
  const model = buildQrModel(value);
  const scale = 16;
  const size = model.dim * scale;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error("Could not render the QR code.");
  }
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = "#111111";
  for (const cell of model.cells) {
    ctx.fillRect(cell.x * scale, cell.y * scale, scale, scale);
  }
  canvas.toBlob((blob) => {
    if (!blob) return;
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
  }, "image/png");
}

function QrCode({ value, size = 168 }: { value: string; size?: number }) {
  const model = useMemo(() => {
    try {
      return buildQrModel(value);
    } catch {
      return null;
    }
  }, [value]);

  if (!model) return null;

  return (
    <svg
      className="qr-code"
      width={size}
      height={size}
      viewBox={`0 0 ${model.dim} ${model.dim}`}
      role="img"
      aria-label="QR code for this page"
      shape-rendering="crispEdges"
    >
      <rect width={model.dim} height={model.dim} fill="#ffffff" />
      {model.cells.map((cell) => (
        <rect
          key={`${cell.x}-${cell.y}`}
          x={cell.x}
          y={cell.y}
          width={1}
          height={1}
          fill="#111111"
        />
      ))}
    </svg>
  );
}

function EmailSignaturePopover({
  tree,
  url,
  onError,
}: {
  tree: LinkTree;
  url: string;
  onError: (message: string) => void;
}) {
  const [copiedKind, setCopiedKind] = useState<
    "" | "rich" | "richPlain" | "plain"
  >("");
  const html = signatureHtml(tree, url);
  const text = signatureText(tree, url);

  const flashCopied = (kind: "rich" | "richPlain" | "plain") => {
    setCopiedKind(kind);
    window.setTimeout(() => setCopiedKind(""), 1800);
  };

  return (
    <div
      popover="auto"
      id="emailSignature"
      className="popover-panel signature-popover"
    >
      <div className="popover-heading">
        <h2>Email signature</h2>
        <button
          type="button"
          className="icon-button"
          aria-label="Close"
          onClick={() =>
            document.getElementById("emailSignature")?.hidePopover()
          }
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>
      <div
        className="signature-preview"
        role="region"
        aria-label="Signature preview"
        dangerouslySetInnerHTML={{ __html: html }}
      ></div>
      <p className="help">
        Copy, then paste into your email app's signature settings.
      </p>
      <div className="popover-actions">
        <button
          type="button"
          aria-live="polite"
          onClick={() => {
            copyRichSignature(html, text)
              .then((rich) => flashCopied(rich ? "rich" : "richPlain"))
              .catch((e) => onError(e.message));
          }}
        >
          {copiedKind === "rich"
            ? "Copied ✓"
            : copiedKind === "richPlain"
              ? "Copied as plain text"
              : "Copy signature"}
        </button>
        <button
          type="button"
          className="secondary"
          aria-live="polite"
          onClick={() => {
            navigator.clipboard
              .writeText(text)
              .then(() => flashCopied("plain"))
              .catch((e) => onError(e.message));
          }}
        >
          {copiedKind === "plain" ? "Copied ✓" : "Copy plain text"}
        </button>
      </div>
    </div>
  );
}

function PageEditor({ priv, pub }: { priv: Signal<Private>; pub: Public }) {
  const ifref = useRef<HTMLIFrameElement>(null);
  const [iframeReady, setIframeReady] = useState(false);

  useEffect(() => {
    if (iframeReady) {
      ifref.current?.contentWindow?.postMessage(
        { type: "preview-update", html: pub.html },
        "*",
      );
    }
  }, [pub.html, iframeReady]);

  return (
    <div className="edit-and-preview">
      <label className="field stack">
        <span className="sr-only">
          {priv.value.type === Type.HTML_PAGE
            ? "HTML content"
            : "Markdown content"}
        </span>
        <textarea
          placeholder={
            priv.value.type === Type.HTML_PAGE
              ? "Start writing HTML"
              : "Start writing GitHub-flavored markdown.\n\nOptional front matter:\n---\ntitle: Page title\n---"
          }
          className="code"
          value={
            priv.value.type === Type.HTML_PAGE ? priv.value.html : priv.value.md
          }
          onInput={(e) => {
            if (priv.value.type === Type.HTML_PAGE) {
              priv.value = {
                ...priv.value,
                html: (e.target as HTMLTextAreaElement).value,
              };
            } else {
              priv.value = {
                ...priv.value,
                md: (e.target as HTMLTextAreaElement).value,
              };
            }
          }}
        ></textarea>
      </label>
      <iframe
        className="preview"
        title="Page preview"
        ref={ifref}
        onLoad={() => setIframeReady(true)}
        srcdoc={`<html><head><script>
window.addEventListener('message', (e) => {
  if (e.data?.type === 'preview-update') {
    const parser = new DOMParser();
    const doc = parser.parseFromString(e.data.html, 'text/html');
    Array.from(doc.documentElement.attributes).forEach(attr => {
      document.documentElement.setAttribute(attr.name, attr.value);
    });
    document.documentElement.innerHTML = e.data.html;
  }
})
</script></head><body></body></html>`}
      ></iframe>
    </div>
  );
}

function RedirectEditor({ priv }: { priv: Signal<Private> }) {
  const normalizedUrl = useMemo(
    () => normalizeUrl(priv.value.redir),
    [priv.value.redir],
  );

  const valid = useMemo(() => URL.canParse(normalizedUrl), [normalizedUrl]);

  return (
    <section className="panel-section">
      <label className="field stack">
        <span>Redirect destination</span>
        <input
          type="url"
          value={priv.value.redir}
          placeholder="example.com"
          aria-describedby="redirect-help"
          onInput={(e) => {
            priv.value = {
              ...priv.value,
              redir: (e.target as HTMLInputElement).value,
            };
          }}
        />
      </label>
      <p id="redirect-help" className={valid ? "help" : "help error-text"}>
        {valid ? normalizedUrl : "Enter a valid web address."}
      </p>
    </section>
  );
}

function FileEditor({
  file,
  setFile,
  onError,
}: {
  file: File | undefined;
  setFile: (file: File | undefined) => void;
  onError: (message: string) => void;
}) {
  return (
    <section className="panel-section">
      <label className="field stack">
        <span>File to publish</span>
        <input
          type="file"
          aria-describedby="file-help"
          onChange={(e) => {
            const target = e.target as HTMLInputElement;
            const selected = target.files?.[0];
            if (!selected) {
              setFile(undefined);
              return;
            }
            if (selected.size > 1024 * 1024) {
              onError("That file is over 1MB. Choose a smaller file.");
              target.value = target.defaultValue;
              setFile(undefined);
              return;
            }
            setFile(selected);
          }}
        />
      </label>
      <p id="file-help" className="help">
        {file
          ? `${file.name} is ready to publish.`
          : "Choose a file under 1MB."}
      </p>
    </section>
  );
}

const handleKinds: LinkKind[] = [
  "instagram",
  "tiktok",
  "x",
  "telegram",
  "github",
  "threads",
  "reddit",
  "twitch",
  "spotify",
  "snapchat",
  "pinterest",
  "medium",
  "patreon",
  "calendly",
  "paypal",
  "venmo",
];

function linkValueLabel(kind: LinkKind): string {
  if (kind === "phone" || kind === "whatsapp") return "Number";
  if (kind === "email") return "Email address";
  if (kind === "address") return "Address or map link";
  if (kind === "discord") return "Invite link";
  if (kind === "cashapp") return "Cashtag or link";
  if (kind === "substack") return "Publication or link";
  if (kind === "mastodon" || kind === "matrix" || kind === "bluesky") {
    return "Handle or link";
  }
  if (handleKinds.includes(kind)) return "Username or link";
  return "Link";
}

function EditableLink({
  link,
  index,
  total,
  updateLink,
  setFeatured,
  setIcon,
  onError,
  removeLink,
  moveTo,
  moveBy,
  dragging,
  setDragging,
  dropTarget,
  setDragOver,
  selected,
  setSelected,
  sectionShown,
}: {
  link: LinkItem;
  index: number;
  total: number;
  updateLink: (link: LinkItem) => void;
  setFeatured: (id: string, featured: boolean) => void;
  setIcon: (id: string, icon: string | undefined) => void;
  onError: (message: string) => void;
  removeLink: () => void;
  moveTo: (draggedId: string, targetId: string) => void;
  moveBy: (id: string, delta: number) => void;
  dragging: boolean;
  setDragging: (id: string) => void;
  dropTarget: boolean;
  setDragOver: (id: string) => void;
  selected: boolean;
  setSelected: (id: string) => void;
  sectionShown: boolean;
}) {
  const normalized = normalizeLink(link);
  const sectionItem = isSection(link);
  const fieldId = `link-${link.id}`;
  const detailId = `${fieldId}-detail`;
  const valueLabel = linkValueLabel(link.kind);
  const label = link.label.trim() || kindLabels[link.kind];
  const optionalIncomplete = Boolean(
    normalized.error && isDefaultLinkValue(link),
  );
  const featurable = Boolean(normalized.href && !normalized.error);
  const featuredShown = Boolean(link.featured && featurable);
  const iconSrc = linkIconSrc(link.icon);
  const iconEmoji = linkIconEmoji(link.icon);
  const iconImportUrl = canImportLinkIcon(normalized.href)
    ? normalized.href
    : kindIconSites[link.kind];
  const iconImportable = !sectionItem && Boolean(iconImportUrl);
  const [importingIcon, setImportingIcon] = useState(false);
  const [iconStatus, setIconStatus] = useState("");

  const importIcon = () => {
    if (!iconImportUrl) return;
    setImportingIcon(true);
    setIconStatus("");
    importLinkIcon(iconImportUrl)
      .then((icon) => {
        setIcon(link.id, icon);
        setIconStatus("Icon saved into your page.");
      })
      .catch((error) => {
        onError((error as Error).message);
      })
      .finally(() => setImportingIcon(false));
  };

  return (
    <article
      className={`editable-link ${selected ? "is-selected" : ""} ${dragging ? "is-dragging" : ""} ${dropTarget ? "is-drop-target" : ""} ${link.enabled ? "" : "is-disabled"} ${sectionItem ? "is-section" : ""} ${featuredShown ? "is-featured" : ""}`}
      draggable
      onDragStart={(event) => {
        if (!event.dataTransfer) return;
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", link.id);
        setDragging(link.id);
      }}
      onDragOver={(event) => {
        event.preventDefault();
        if (event.dataTransfer) {
          event.dataTransfer.dropEffect = "move";
        }
        if (!dragging) {
          setDragOver(link.id);
        }
      }}
      onDrop={(event) => {
        event.preventDefault();
        const draggedId = event.dataTransfer?.getData("text/plain") ?? "";
        moveTo(draggedId, link.id);
        setDragging("");
        setDragOver("");
      }}
      onDragEnd={() => {
        setDragging("");
        setDragOver("");
      }}
    >
      <div className="editable-link-row">
        <span className="reorder" title="Drag to reorder">
          <span className="drag-grip" aria-hidden="true"></span>
          <button
            type="button"
            className="reorder-button"
            aria-label={`Move ${label} up`}
            disabled={index === 0}
            onClick={() => moveBy(link.id, -1)}
          >
            <span aria-hidden="true">▲</span>
          </button>
          <button
            type="button"
            className="reorder-button"
            aria-label={`Move ${label} down`}
            disabled={index === total - 1}
            onClick={() => moveBy(link.id, 1)}
          >
            <span aria-hidden="true">▼</span>
          </button>
        </span>
        <button
          type="button"
          className="contact-button-preview"
          aria-expanded={selected}
          aria-controls={selected ? detailId : undefined}
          onClick={() => setSelected(selected ? "" : link.id)}
        >
          {iconSrc ? (
            <img className="row-link-icon" src={iconSrc} alt="" />
          ) : iconEmoji ? (
            <span className="row-link-emoji" aria-hidden="true">
              {iconEmoji}
            </span>
          ) : null}
          {featuredShown && (
            <span className="featured-tag">
              <span aria-hidden="true">★ </span>Featured
            </span>
          )}
          {label}
        </button>
        <button
          type="button"
          className="icon-button"
          aria-label={`Remove ${label}`}
          title="Remove"
          onClick={removeLink}
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>

      {selected && (
        <div className="link-edit-panel" id={detailId}>
          <label className="field stack">
            <span>{sectionItem ? "Section text" : "Button text"}</span>
            <input
              type="text"
              value={link.label}
              placeholder={
                sectionItem ? kindExamples.section : kindLabels[link.kind]
              }
              aria-describedby={sectionItem ? `${detailId}-status` : undefined}
              onInput={(e) =>
                updateLink({
                  ...link,
                  label: (e.target as HTMLInputElement).value,
                })
              }
            />
          </label>
          {!sectionItem && (
            <div className="panel-group">
              <label className="field stack">
                <span>{valueLabel}</span>
                <input
                  id={fieldId}
                  type={link.kind === "email" ? "email" : "text"}
                  value={link.value}
                  placeholder={kindExamples[link.kind]}
                  aria-describedby={`${detailId}-status`}
                  onInput={(e) =>
                    updateLink({
                      ...link,
                      value: (e.target as HTMLInputElement).value,
                    })
                  }
                />
              </label>
              {link.kind === "email" && (
                <p className="help">
                  Need a public email address? Create a forwarding alias at{" "}
                  <a href="https://cc.me/hi" target="_blank" rel="noreferrer">
                    cc.me/hi
                  </a>
                  .
                </p>
              )}
            </div>
          )}
          <label className="show-toggle">
            <input
              type="checkbox"
              checked={link.enabled}
              onChange={(e) =>
                updateLink({
                  ...link,
                  enabled: (e.target as HTMLInputElement).checked,
                })
              }
            />
            <span>Show on page</span>
          </label>
          {canFeature(link) && (
            <label className="show-toggle">
              <input
                type="checkbox"
                checked={Boolean(link.featured)}
                disabled={!link.featured && !featurable}
                onChange={(e) =>
                  setFeatured(link.id, (e.target as HTMLInputElement).checked)
                }
              />
              <span>Feature this link</span>
            </label>
          )}
          {identityKinds.has(link.kind) && (
            <div className="panel-group">
              <label className="show-toggle">
                <input
                  type="checkbox"
                  checked={link.relMe !== false}
                  aria-describedby={`${detailId}-relme`}
                  onChange={(e) =>
                    updateLink({
                      ...link,
                      relMe: (e.target as HTMLInputElement).checked,
                    })
                  }
                />
                <span>This is really me</span>
              </label>
              <p id={`${detailId}-relme`} className="help">
                Publishes this link with rel="me", which tells other sites it's
                yours — Mastodon uses it for its green "verified" check. Untick
                it if this link isn't your own.
              </p>
            </div>
          )}
          {!sectionItem && (
            <div className="link-icon-block">
              <div className="link-icon-actions">
                {(iconSrc || iconEmoji) && (
                  <span className="link-icon-preview" aria-hidden="true">
                    {iconSrc ? <img src={iconSrc} alt="" /> : iconEmoji}
                  </span>
                )}
                <input
                  type="text"
                  className="emoji-input"
                  aria-label="Emoji icon"
                  value={iconEmoji ?? ""}
                  placeholder={kindDefaultIcons[link.kind] ?? "😀"}
                  onInput={(e) => {
                    const graphemes = splitGraphemes(
                      (e.target as HTMLInputElement).value.trim(),
                    );
                    const fresh = iconEmoji
                      ? graphemes.filter((g) => g !== iconEmoji)
                      : graphemes;
                    const picked = fresh.length ? fresh : graphemes;
                    setIcon(
                      link.id,
                      picked.length ? picked[picked.length - 1] : undefined,
                    );
                    setIconStatus("");
                  }}
                />
                {iconImportable && (
                  <button
                    type="button"
                    className="secondary"
                    disabled={importingIcon}
                    onClick={importIcon}
                  >
                    {importingIcon
                      ? "Importing…"
                      : iconSrc
                        ? "Refresh icon"
                        : "Import icon"}
                  </button>
                )}
                {(iconSrc || iconEmoji) && (
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      setIcon(link.id, undefined);
                      setIconStatus("");
                    }}
                  >
                    Remove icon
                  </button>
                )}
              </div>
              <p className="help">
                {iconStatus ||
                  (iconImportable
                    ? "Show an icon on this button — type an emoji, or import the site's icon. It's fetched once and saved into your page."
                    : "Show an icon on this button — type any emoji.")}
              </p>
            </div>
          )}
          {sectionItem ? (
            <p id={`${detailId}-status`} className="link-status">
              {sectionShown
                ? "Shown as a heading."
                : !link.label.trim()
                  ? "Hidden until it has text."
                  : link.enabled
                    ? "Hidden until a link below it is shown."
                    : "Hidden."}
            </p>
          ) : (
            <p
              id={`${detailId}-status`}
              className={`link-status ${
                normalized.error && !optionalIncomplete
                  ? "error-text"
                  : normalized.warning
                    ? "warning-text"
                    : ""
              }`}
            >
              {(optionalIncomplete ? undefined : normalized.error) ??
                normalized.warning ??
                (normalized.href
                  ? normalized.href
                  : link.featured
                    ? "Featured — hidden until complete."
                    : "Hidden until complete.")}
            </p>
          )}
        </div>
      )}
      <span className="sr-only">
        {index + 1} of {total}
      </span>
    </article>
  );
}

function AvatarUpload({
  value,
  onChange,
  onError,
}: {
  value: string | undefined;
  onChange: (value: string) => void;
  onError: (message: string) => void;
}) {
  const [status, setStatus] = useState<string>("");
  const src = avatarImageSrc(value);

  return (
    <div className={`avatar-upload ${src ? "has-avatar" : ""}`}>
      {src && (
        <div className="avatar-upload-preview" aria-hidden="true">
          <img src={src} alt="" />
        </div>
      )}
      <div className="avatar-upload-controls">
        <div className="avatar-upload-actions">
          <label className="button-link secondary">
            {src ? "Replace photo" : "Add photo"}
            <input
              type="file"
              accept="image/*"
              className="sr-only"
              onChange={(e) => {
                const input = e.target as HTMLInputElement;
                const file = input.files?.[0];
                input.value = "";
                if (!file) return;
                setStatus("Compressing...");
                compressAvatar(file)
                  .then((avatar) => {
                    onChange(avatar.dataUrl);
                    setStatus(
                      `${avatar.mime === "image/avif" ? "AVIF" : "JPEG"} avatar ready.`,
                    );
                  })
                  .catch((error) => {
                    setStatus("");
                    onError(error.message);
                  });
              }}
            />
          </label>
          {src && (
            <button
              type="button"
              className="secondary"
              onClick={() => {
                onChange("");
                setStatus("");
              }}
            >
              Remove
            </button>
          )}
        </div>
        {status && <p className="help">{status}</p>}
      </div>
    </div>
  );
}

function LinkTreeEditor({
  priv,
  displayAddress,
  onError,
}: {
  priv: Signal<Private>;
  displayAddress: string;
  onError: (message: string) => void;
}) {
  const tree = ensureLinkTree(priv.value.linkTree);
  const shownSections = shownSectionIds(tree);
  const [draggingId, setDraggingId] = useState("");
  const [dragOverId, setDragOverId] = useState("");
  const [selectedLinkId, setSelectedLinkId] = useState("");
  const [ogPreview, setOgPreview] = useState("");

  const autoImageOn =
    (tree.social?.autoImage ?? true) &&
    !socialImageUrl(tree.social?.imageUrl) &&
    priv.value.type === Type.LINK_TREE;
  useEffect(() => {
    if (!autoImageOn) {
      setOgPreview((prev) => {
        if (prev) URL.revokeObjectURL(prev);
        return "";
      });
      return;
    }
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      renderOgImage(ensureLinkTree(priv.value.linkTree), displayAddress)
        .then((bytes) => {
          if (cancelled || !bytes) return;
          setOgPreview((prev) => {
            if (prev) URL.revokeObjectURL(prev);
            return URL.createObjectURL(
              new Blob([bytes as Uint8Array<ArrayBuffer>], {
                type: "image/png",
              }),
            );
          });
        })
        .catch(() => {});
    }, 400);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [
    autoImageOn,
    displayAddress,
    tree.displayName,
    tree.bio,
    tree.theme,
    tree.accent,
    tree.avatarUrl,
  ]);

  const updateTree = (nextTree: LinkTree) => {
    priv.value = {
      ...priv.value,
      type: Type.LINK_TREE,
      linkTree: nextTree,
    };
  };

  const social = tree.social ?? {};
  const updateSocial = (patch: Partial<SocialPreview>) => {
    updateTree({ ...tree, social: { ...social, ...patch } });
  };
  const socialImageInvalid = Boolean(
    social.imageUrl?.trim() && !socialImageUrl(social.imageUrl),
  );

  const updateLink = (link: LinkItem) => {
    updateTree({
      ...tree,
      links: tree.links.map((current) =>
        current.id === link.id
          ? { ...link, href: normalizeLink(link).href }
          : current,
      ),
    });
  };

  const setFeatured = (id: string, featured: boolean) => {
    updateTree({
      ...tree,
      links: tree.links.map((link) => ({
        ...link,
        featured: featured && link.id === id ? true : undefined,
      })),
    });
  };

  const setIcon = (id: string, icon: string | undefined) => {
    const current = ensureLinkTree(priv.value.linkTree);
    updateTree({
      ...current,
      links: current.links.map((link) =>
        link.id === id ? { ...link, icon } : link,
      ),
    });
  };

  const addLinkOfKind = (kind: LinkKind) => {
    const link = defaultLinkItem(kind);
    updateTree({
      ...tree,
      links: [...tree.links, link],
    });
    setSelectedLinkId(link.id);
  };

  const moveLinkBy = (id: string, delta: number) => {
    const fromIndex = tree.links.findIndex((link) => link.id === id);
    const toIndex = fromIndex + delta;
    if (fromIndex < 0 || toIndex < 0 || toIndex >= tree.links.length) {
      return;
    }
    const nextLinks = [...tree.links];
    const [link] = nextLinks.splice(fromIndex, 1);
    nextLinks.splice(toIndex, 0, link);
    updateTree({ ...tree, links: nextLinks });
  };

  const removeLink = (id: string) => {
    updateTree({
      ...tree,
      links: tree.links.filter((link) => link.id !== id),
    });
    if (selectedLinkId === id) {
      setSelectedLinkId("");
    }
  };

  const moveLinkTo = (draggedId: string, targetId: string) => {
    if (!draggedId || draggedId === targetId) {
      return;
    }
    const fromIndex = tree.links.findIndex((link) => link.id === draggedId);
    const toIndex = tree.links.findIndex((link) => link.id === targetId);
    if (fromIndex < 0 || toIndex < 0) {
      return;
    }
    const nextLinks = [...tree.links];
    const [link] = nextLinks.splice(fromIndex, 1);
    nextLinks.splice(toIndex, 0, link);
    updateTree({ ...tree, links: nextLinks });
  };

  return (
    <section className="live-editor" aria-label="Contact page editor">
      <div
        className={`live-page theme-${tree.theme || "system"} ${accentPair(tree.accent) ? "accent-custom" : ""}`}
        style={
          accentPair(tree.accent)
            ? {
                "--pv-a-light": accentPair(tree.accent)!.light,
                "--pv-a-dark": accentPair(tree.accent)!.dark,
              }
            : undefined
        }
      >
        <div className="live-profile">
          <AvatarUpload
            value={tree.avatarUrl}
            onChange={(avatarUrl) => updateTree({ ...tree, avatarUrl })}
            onError={onError}
          />
          <input
            className="live-name"
            aria-label="Name"
            type="text"
            value={tree.displayName}
            placeholder="Ada Lovelace"
            onInput={(e) =>
              updateTree({
                ...tree,
                displayName: (e.target as HTMLInputElement).value,
              })
            }
          />
          <textarea
            className="live-bio"
            aria-label="Short description"
            rows={3}
            value={tree.bio}
            placeholder="Mathematician · first computer programmer"
            onInput={(e) =>
              updateTree({
                ...tree,
                bio: (e.target as HTMLTextAreaElement).value,
              })
            }
          ></textarea>
        </div>

        <div className="editable-links" aria-label="Contact buttons">
          {tree.links.length > 0 ? (
            tree.links.map((link, index) => (
              <EditableLink
                key={link.id}
                link={link}
                index={index}
                total={tree.links.length}
                updateLink={updateLink}
                setFeatured={setFeatured}
                setIcon={setIcon}
                onError={onError}
                removeLink={() => removeLink(link.id)}
                moveTo={moveLinkTo}
                moveBy={moveLinkBy}
                dragging={draggingId === link.id}
                setDragging={setDraggingId}
                dropTarget={dragOverId === link.id && draggingId !== link.id}
                setDragOver={setDragOverId}
                selected={selectedLinkId === link.id}
                setSelected={setSelectedLinkId}
                sectionShown={shownSections.has(link.id)}
              />
            ))
          ) : (
            <div className="empty-list">
              <p>No contact buttons yet.</p>
            </div>
          )}
        </div>

        <div className="add-section">
          <span className="add-label">Add a link</span>
          <div className="add-chips">
            {[...recommendedKinds, ...additionalKinds].map((kind) => (
              <button
                type="button"
                className="add-link-item"
                key={kind}
                onClick={() => addLinkOfKind(kind)}
              >
                <span className="add-link-plus" aria-hidden="true">
                  +
                </span>
                {kindLabels[kind]}
              </button>
            ))}
          </div>
          <span className="add-label">Organize</span>
          <div className="add-chips">
            <button
              type="button"
              className="add-link-item"
              onClick={() => addLinkOfKind("section")}
            >
              <span className="add-link-plus" aria-hidden="true">
                +
              </span>
              {kindLabels.section}
            </button>
          </div>
        </div>
      </div>

      <fieldset className="theme-picker">
        <legend>Theme</legend>
        {(
          ["system", "light", "dark", "warm", "clean"] as LinkTree["theme"][]
        ).map((theme) => (
          <label className={`theme-choice swatch-${theme}`} key={theme}>
            <input
              type="radio"
              name="theme"
              value={theme}
              checked={tree.theme === theme}
              onChange={() => updateTree({ ...tree, theme })}
            />
            <span>{theme[0].toUpperCase() + theme.slice(1)}</span>
          </label>
        ))}
        <div className="accent-row">
          <span className="accent-row-label">Accent</span>
          <label className="accent-choice" title="Theme default">
            <input
              type="radio"
              name="accent"
              checked={!accentPair(tree.accent)}
              onChange={() => updateTree({ ...tree, accent: "" })}
            />
            <span
              className="accent-dot"
              style={{ background: themeAccentDefaults[tree.theme] }}
            ></span>
            <span className="sr-only">Theme default</span>
          </label>
          {Object.entries(accentPalette).map(([key, pair]) => (
            <label
              className="accent-choice"
              key={key}
              title={key[0].toUpperCase() + key.slice(1)}
            >
              <input
                type="radio"
                name="accent"
                checked={tree.accent === key}
                onChange={() => updateTree({ ...tree, accent: key })}
              />
              <span
                className="accent-dot"
                style={{
                  background: `linear-gradient(135deg, ${pair.light} 50%, ${pair.dark} 50%)`,
                }}
              ></span>
              <span className="sr-only">{key}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <div className="vcard-toggle-panel">
        <label className="show-toggle">
          <input
            type="checkbox"
            checked={tree.showVcard !== false}
            onChange={(e) =>
              updateTree({
                ...tree,
                showVcard: (e.target as HTMLInputElement).checked,
              })
            }
          />
          <span>Show a "Save contact" button</span>
        </label>
        <p className="help">
          {vcardEligible(tree)
            ? "Lets visitors download a contact card (.vcf) with your details."
            : "Lets visitors download a contact card (.vcf). The button appears once your page has a name and a shown phone or email."}
        </p>
      </div>

      <details className="social-preview-panel">
        <summary>Social preview</summary>
        <p className="help">
          Shown when someone shares found.as links on X, LinkedIn, iMessage, and
          similar apps. Leave fields blank to use your name and description.
        </p>
        <label className="show-toggle">
          <input
            type="checkbox"
            checked={social.autoImage ?? true}
            onChange={(e) =>
              updateSocial({
                autoImage: (e.target as HTMLInputElement).checked,
              })
            }
          />
          <span>Create a preview image automatically</span>
        </label>
        {ogPreview && (
          <img
            className="og-preview"
            src={ogPreview}
            alt="Preview image that will be published"
            width={1200}
            height={630}
          />
        )}
        <label className="field stack">
          <span>Preview title</span>
          <input
            type="text"
            value={social.title ?? ""}
            placeholder={tree.displayName.trim() || "Ada Lovelace"}
            onInput={(e) =>
              updateSocial({ title: (e.target as HTMLInputElement).value })
            }
          />
        </label>
        <label className="field stack">
          <span>Preview description</span>
          <input
            type="text"
            value={social.description ?? ""}
            placeholder={
              tree.bio.trim() || "Mathematician · first computer programmer"
            }
            onInput={(e) =>
              updateSocial({
                description: (e.target as HTMLInputElement).value,
              })
            }
          />
        </label>
        <label className="field stack">
          <span>Preview image address</span>
          <input
            type="url"
            value={social.imageUrl ?? ""}
            placeholder="https://example.com/card.jpg"
            aria-describedby="social-image-help"
            aria-invalid={socialImageInvalid}
            onInput={(e) =>
              updateSocial({ imageUrl: (e.target as HTMLInputElement).value })
            }
          />
        </label>
        <p
          id="social-image-help"
          className={socialImageInvalid ? "help error-text" : "help"}
        >
          {socialImageInvalid
            ? "Enter a full https:// image address, or leave it blank."
            : "Optional — replaces the automatic image. A hosted https image, ideally 1200×630 pixels."}
        </p>
      </details>
    </section>
  );
}

function BuilderModePicker({
  mode,
  setMode,
  advancedType,
  setAdvancedType,
}: {
  mode: BuilderMode;
  setMode: (mode: BuilderMode) => void;
  advancedType: Type;
  setAdvancedType: (type: Type) => void;
}) {
  return (
    <section className="intent-panel" aria-labelledby="intent-title">
      <div className="section-heading">
        <p className="eyebrow">Page type</p>
        <h2 id="intent-title">What should this page do?</h2>
      </div>
      <div className="intent-grid">
        <label className="intent-option">
          <input
            type="radio"
            name="builder-mode"
            value="contact"
            checked={mode === "contact"}
            onChange={() => setMode("contact")}
          />
          <span>
            <strong>Contact page</strong>
            <small>Links for web, email, social, phone, and more.</small>
          </span>
        </label>
        <label className="intent-option">
          <input
            type="radio"
            name="builder-mode"
            value="advanced"
            checked={mode === "advanced"}
            onChange={() => setMode("advanced")}
          />
          <span>
            <strong>Advanced publishing</strong>
            <small>Redirect, markdown page, HTML page, or file.</small>
          </span>
        </label>
      </div>
      {mode === "advanced" && (
        <AdvancedModePicker value={advancedType} setValue={setAdvancedType} />
      )}
    </section>
  );
}

function AdvancedModePicker({
  value,
  setValue,
}: {
  value: Type;
  setValue: (type: Type) => void;
}) {
  const modes: { type: Type; label: string; description: string }[] = [
    {
      type: Type.REDIR,
      label: "Redirect",
      description: "Send visitors to one web address.",
    },
    {
      type: Type.MARKDOWN_PAGE,
      label: "Markdown",
      description: "Write a simple page with Markdown.",
    },
    {
      type: Type.HTML_PAGE,
      label: "HTML",
      description: "Publish a custom HTML page.",
    },
    {
      type: Type.BYTES,
      label: "File",
      description: "Host one file up to 1MB.",
    },
  ];

  return (
    <fieldset className="advanced-mode-picker">
      <legend>Advanced format</legend>
      <div className="advanced-mode-grid">
        {modes.map((mode) => (
          <label className="advanced-mode-option" key={mode.type}>
            <input
              type="radio"
              name="advanced-type"
              value={mode.type}
              checked={value === mode.type}
              onChange={() => setValue(mode.type)}
            />
            <span>
              <strong>{mode.label}</strong>
              <small>{mode.description}</small>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function publishLabel(type: Type): string {
  if (type === Type.LINK_TREE) return "Publish contact page";
  if (type === Type.REDIR) return "Publish redirect";
  if (type === Type.MARKDOWN_PAGE) return "Publish markdown page";
  if (type === Type.HTML_PAGE) return "Publish HTML page";
  return "Publish file";
}

function modeSummary(type: Type): string {
  if (type === Type.LINK_TREE) return "Contact page";
  if (type === Type.REDIR) return "Redirect";
  if (type === Type.MARKDOWN_PAGE) return "Markdown page";
  if (type === Type.HTML_PAGE) return "HTML page";
  return "File";
}

function SetupPanel({
  path,
  setPath,
  pw,
  setPw,
  working,
  pwStatus,
  pathIsNew,
  onContinue,
}: {
  path: string;
  setPath: (path: string) => void;
  pw: string;
  setPw: (pw: string) => void;
  working: boolean;
  pwStatus: boolean | undefined;
  pathIsNew: boolean;
  onContinue: () => void;
}) {
  const [revealPw, setRevealPw] = useState(false);
  const hasPath = path.trim().length > 0;
  const canContinue = pwStatus === true && !working;
  const isNew = pwStatus === true && pathIsNew;
  const isExisting = pwStatus === true && !pathIsNew;

  const availability = !hasPath
    ? null
    : working
      ? { className: "help", text: "Checking availability…" }
      : isNew
        ? {
            className: "help available-text",
            text: `found.as/${path.trim()} is available.`,
          }
        : isExisting
          ? {
              className: "help",
              text: "This address already exists — password unlocked. Continue to edit it.",
            }
          : pwStatus === false
            ? {
                className: "help error-text",
                text: "This address exists. Enter its password to edit, or pick another address.",
              }
            : null;

  // Capitals and punctuation work, but make a link harder to type and share
  // (and the address is case-sensitive), so nudge toward a clean slug.
  const pathTrimmed = path.trim();
  const pathDiscouraged = pathTrimmed !== "" && /[^a-z0-9/-]/.test(pathTrimmed);

  return (
    <section className="setup-panel" aria-labelledby="setup-title">
      <div className="setup-copy">
        <p className="eyebrow">found.as</p>
        <h1 id="setup-title">Online in seconds</h1>
        <p>Pick an address and a password. No account, no cookies.</p>
      </div>
      <form
        className="setup-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (canContinue) {
            onContinue();
          }
        }}
      >
        <label className="field stack">
          <span>Your address</span>
          <span className="path-field">
            <span className="path-prefix">found.as/</span>
            <input
              type="text"
              aria-label="Page path"
              maxLength={64}
              value={path}
              autoComplete="off"
              autoCapitalize="off"
              spellcheck={false}
              aria-describedby={availability ? "setup-path-status" : undefined}
              onInput={(e) => setPath((e.target as HTMLInputElement).value)}
            />
          </span>
        </label>
        {pathDiscouraged && (
          <p className="help warning-text">
            Lowercase letters, numbers and hyphens make the best address —
            capitals and special characters are harder to type and share.
          </p>
        )}
        {availability && (
          <p id="setup-path-status" className={availability.className}>
            {availability.text}
          </p>
        )}
        <label className="field stack">
          <span>{isExisting ? "Page password" : "Create a password"}</span>
          <span className="path-field reveal-field">
            <input
              type={revealPw ? "text" : "password"}
              value={pw}
              autoComplete={isExisting ? "current-password" : "new-password"}
              placeholder={
                pwStatus === false
                  ? "Enter the existing password"
                  : "Use this to edit later"
              }
              aria-invalid={pwStatus === false}
              onInput={(e) => setPw((e.target as HTMLInputElement).value)}
            />
            <button
              type="button"
              className="reveal-toggle"
              aria-pressed={revealPw}
              onClick={() => setRevealPw((v) => !v)}
            >
              {revealPw ? "Hide" : "Show"}
            </button>
          </span>
        </label>
        {isNew && pw === "" && (
          <p className="help warning-text">
            Blank password — anyone who opens this editor address can change
            your page.
          </p>
        )}
        <p className="help recovery-note">
          There is no password reset. Once you're in, save the recovery kit from
          the menu — it keeps your address and password somewhere safe.
        </p>
        <div className="action-row">
          <button type="submit" disabled={!canContinue}>
            {isExisting ? "Edit page" : "Create page"}
          </button>
        </div>
      </form>
    </section>
  );
}

let postSingleton: AbortController | null = null;

async function post(body: any) {
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

async function updateData(
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

async function updatePw(
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

async function renamePage(
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

async function deletePage(keyPair: SignKeyPair, path: string): Promise<void> {
  const response = await post([
    9,
    keyPair.publicKey,
    sign(encode([new Date().getTime() / 1000, path]), keyPair.secretKey),
  ]);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

async function fetchData(keyPair: SignKeyPair, path: string): Promise<Private> {
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

interface DomainStatus {
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
async function domainRequest(
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

async function mapCustomDomain(
  keyPair: SignKeyPair,
  path: string,
  domain: string,
): Promise<void> {
  await domainRequest(4, keyPair, path, domain);
}

async function unmapCustomDomain(
  keyPair: SignKeyPair,
  path: string,
  domain: string,
): Promise<void> {
  await domainRequest(5, keyPair, path, domain);
}

async function customDomainStatus(
  keyPair: SignKeyPair,
  path: string,
  domain: string,
): Promise<DomainStatus> {
  const response = await domainRequest(6, keyPair, path, domain);
  return decode(new Uint8Array(await response.arrayBuffer()));
}

async function listCustomDomains(
  keyPair: SignKeyPair,
  path: string,
): Promise<string[]> {
  const response = await domainRequest(7, keyPair, path, "");
  return decode(new Uint8Array(await response.arrayBuffer())) ?? [];
}

function normalizeDomainInput(value: string): string | null {
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

interface PendingDomain {
  domain: string;
  state: "waiting" | "securing";
  target: string;
  label: string;
  isApex: boolean;
}

function DnsRow({ type, value }: { type: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <span>{type}</span>
      <code>{value}</code>
      <button
        type="button"
        className="dns-copy"
        aria-label={`Copy ${type} value`}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          } catch {
            // clipboard blocked — the value is still selectable by hand
          }
        }}
      >
        {copied ? "Copied ✓" : "Copy"}
      </button>
    </div>
  );
}

function DomainPopover({
  kp,
  path,
  shareDomain,
  setShareDomain,
  onError,
}: {
  kp: SignKeyPair;
  path: string;
  shareDomain: string | null;
  setShareDomain: (d: string | null) => void;
  onError: (message: string) => void;
}) {
  const [domains, setDomains] = useState<string[] | null>(null);
  const [statuses, setStatuses] = useState<Record<string, DomainStatus>>({});
  const [input, setInput] = useState("");
  const [pending, setPending] = useState<PendingDomain | null>(null);
  const [busy, setBusy] = useState(false);
  const [justConnected, setJustConnected] = useState("");
  const [lastStatus, setLastStatus] = useState<{
    domain: string;
    status: DomainStatus;
  } | null>(null);
  const checkNow = useRef<(() => void) | null>(null);

  const refresh = async () => {
    try {
      const list = await listCustomDomains(kp, path);
      setDomains(list);
      const next: Record<string, DomainStatus> = {};
      for (const domain of list) {
        try {
          next[domain] = await customDomainStatus(kp, path, domain);
        } catch {
          // shown as unknown until the next refresh
        }
      }
      setStatuses(next);
    } catch (e) {
      onError((e as Error).message);
    }
  };

  useEffect(() => {
    const panel = document.getElementById("customDomain");
    if (!panel) {
      return;
    }
    const onToggle = (e: Event) => {
      if ((e as ToggleEvent).newState !== "open") {
        return;
      }
      if (domains === null) {
        refresh();
      }
    };
    panel.addEventListener("toggle", onToggle);
    return () => panel.removeEventListener("toggle", onToggle);
  }, [domains, kp, path]);

  useEffect(() => {
    if (!pending) {
      return;
    }
    const domain = pending.domain;
    let cancelled = false;
    const tick = async () => {
      try {
        const status = await customDomainStatus(kp, path, domain);
        if (cancelled) {
          return;
        }
        setLastStatus({ domain, status });
        if (status.conflict) {
          setPending(null);
          onError("This domain is already connected to another page.");
          return;
        }
        if (status.certPaused) {
          setPending(null);
          onError(
            `We couldn't secure ${domain} after repeated attempts. Remove it, check your DNS records, and try again.`,
          );
          refresh();
          return;
        }
        if (status.mapped && status.cert) {
          setPending(null);
          setJustConnected(domain);
          refresh();
          return;
        }
        if (!status.mapped && status.bound && status.reachable) {
          await mapCustomDomain(kp, path, domain);
          if (!cancelled) {
            setPending({ ...pending, domain, state: "securing" });
          }
          return;
        }
        if (status.mapped && pending.state !== "securing") {
          setPending({ ...pending, domain, state: "securing" });
        }
      } catch {
        // transient — checked again on the next tick
      }
    };
    checkNow.current = tick;
    tick();
    // While waiting on DNS, poll slower than the server's ~10s reachability
    // probe so checks never overlap; once securing, a cert usually lands in
    // seconds, so check more eagerly.
    const interval = window.setInterval(
      tick,
      pending.state === "securing" ? 4000 : 15000,
    );
    return () => {
      cancelled = true;
      checkNow.current = null;
      window.clearInterval(interval);
    };
  }, [pending?.domain, pending?.state, kp, path]);

  const connect = async () => {
    const domain = normalizeDomainInput(input);
    if (!domain) {
      onError("Enter a domain like yourname.com.");
      return;
    }
    setBusy(true);
    try {
      const status = await customDomainStatus(kp, path, domain);
      if (status.conflict) {
        onError("This domain is already connected to another page.");
        return;
      }
      setJustConnected("");
      setInput("");
      setLastStatus({ domain, status });
      if (status.mapped && status.cert) {
        await refresh();
        return;
      }
      const base = {
        domain,
        target: status.target,
        label: status.label,
        isApex: status.apex,
      };
      if (status.mapped || (status.bound && status.reachable)) {
        if (!status.mapped) {
          await mapCustomDomain(kp, path, domain);
        }
        setPending({ ...base, state: "securing" });
      } else {
        setPending({ ...base, state: "waiting" });
      }
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (domain: string) => {
    setBusy(true);
    try {
      await unmapCustomDomain(kp, path, domain);
      if (pending?.domain === domain) {
        setPending(null);
      }
      if (justConnected === domain) {
        setJustConnected("");
      }
      if (shareDomain === domain) {
        setShareDomain(null);
      }
      await refresh();
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const listed = (domains ?? []).filter((d) => d !== pending?.domain);
  const liveDomains = (domains ?? []).filter((d) => statuses[d]?.cert);

  const cnameInstructions = (p: PendingDomain) => (
    <>
      <p>
        Sign in wherever you manage <strong>{p.domain}</strong>'s DNS — usually
        where you bought it — and add a CNAME record:
      </p>
      <div className="dns-records">
        <DnsRow type="CNAME" value={p.target} />
      </div>
      <p className="help">
        One CNAME on <code>{p.domain}</code> pointing to the address above. It
        connects the domain and proves it's yours in a single record.
      </p>
    </>
  );

  const apexInstructions = (p: PendingDomain) => (
    <>
      <p>
        A bare domain can't use a CNAME, so it takes two steps. First, if your
        DNS provider offers an ALIAS or ANAME record (or CNAME flattening),
        point <strong>{p.domain}</strong> at this name — we keep it aimed at our
        servers, so it never needs updating:
      </p>
      <div className="dns-records">
        <DnsRow type="ALIAS" value={p.target} />
      </div>
      <p className="help">
        Then add this record so we know the domain is yours:
      </p>
      <div className="dns-records">
        <DnsRow type="TXT" value={`found=${p.label}`} />
      </div>
      <p className="help">
        No ALIAS support? Use a subdomain like <code>www.{p.domain}</code>{" "}
        instead — it takes a plain CNAME.
      </p>
    </>
  );

  // Turn the separate bound/reachable signals into a plain-language "you're
  // halfway" nudge, so a bare-domain owner who added the addresses but skipped
  // the TXT (or vice versa) knows exactly which record is still missing.
  const diagnostic = (p: PendingDomain) => {
    if (!lastStatus || lastStatus.domain !== p.domain) {
      return null;
    }
    const s = lastStatus.status;
    if (s.reachable && !s.bound) {
      return (
        <p className="help domain-progress" aria-live="polite">
          ✓ {p.domain} is reaching us. Now add the record that proves it's yours
          — the {p.isApex ? "TXT record" : "CNAME"} below.
        </p>
      );
    }
    if (s.bound && !s.reachable) {
      return (
        <p className="help domain-progress" aria-live="polite">
          ✓ We can see your proof record — now waiting for {p.domain} to route
          to us, usually just the DNS change spreading.
        </p>
      );
    }
    return null;
  };

  const pendingActions = (p: PendingDomain) => (
    <div className="popover-actions domain-actions">
      <button
        type="button"
        disabled={busy}
        onClick={() => checkNow.current?.()}
      >
        Check now
      </button>
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() => remove(p.domain)}
      >
        Cancel
      </button>
    </div>
  );

  return (
    <div
      popover="auto"
      id="customDomain"
      className="popover-panel domain-popover"
    >
      <div className="popover-heading">
        <h2>Custom domains</h2>
        <button
          type="button"
          className="icon-button"
          aria-label="Close"
          onClick={() => document.getElementById("customDomain")?.hidePopover()}
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>
      <p className="help">
        A domain you own can show this page. Your found.as address keeps working
        — the domain is an extra way in, and you can remove it anytime.
      </p>
      {domains === null ? (
        <p className="help">Loading…</p>
      ) : (
        <>
          {listed.map((domain) => {
            const status = statuses[domain];
            return (
              <div className="domain-row" key={domain}>
                <a href={`https://${domain}/`} target="_blank" rel="noreferrer">
                  {domain}
                </a>
                <span className="help">
                  {status === undefined
                    ? ""
                    : status.cert
                      ? "live"
                      : status.certPaused
                        ? "needs attention"
                        : "securing…"}
                </span>
                <button
                  type="button"
                  className="secondary"
                  disabled={busy}
                  onClick={() => remove(domain)}
                >
                  Remove
                </button>
              </div>
            );
          })}
          {justConnected && (
            <p className="help" aria-live="polite">
              🎉{" "}
              <a
                href={`https://${justConnected}/`}
                target="_blank"
                rel="noreferrer"
              >
                https://{justConnected}
              </a>{" "}
              is live.
            </p>
          )}
          {liveDomains.length > 0 && (
            <fieldset className="main-address">
              <legend>Main address</legend>
              <p className="help">
                The address featured on your QR code, printables and email
                signature. Your page stays reachable at every address either
                way.
              </p>
              <label className="main-address-option">
                <input
                  type="radio"
                  name="main-address"
                  checked={shareDomain === null}
                  onChange={() => setShareDomain(null)}
                />
                <span>found.as/{path}</span>
              </label>
              {liveDomains.map((domain) => (
                <label className="main-address-option" key={domain}>
                  <input
                    type="radio"
                    name="main-address"
                    checked={shareDomain === domain}
                    onChange={() => setShareDomain(domain)}
                  />
                  <span>{domain}</span>
                </label>
              ))}
            </fieldset>
          )}
          {pending ? (
            <div className="domain-pending">
              {pending.state === "waiting" ? (
                <>
                  <p>
                    <strong>{pending.domain}</strong> isn't connected yet.
                  </p>
                  {diagnostic(pending)}
                  {pending.isApex ? (
                    <>
                      {apexInstructions(pending)}
                      <details className="domain-apex">
                        <summary>
                          On a subdomain instead (like www.{pending.domain})?
                        </summary>
                        {cnameInstructions(pending)}
                      </details>
                    </>
                  ) : (
                    <>
                      {cnameInstructions(pending)}
                      <details className="domain-apex">
                        <summary>Using a bare domain like example.com?</summary>
                        {apexInstructions(pending)}
                      </details>
                    </>
                  )}
                  <p className="help" aria-live="polite">
                    We check every few seconds — you can close this window and
                    come back later.
                  </p>
                  {pendingActions(pending)}
                </>
              ) : (
                <>
                  <p aria-live="polite">
                    Found it! Securing <strong>{pending.domain}</strong> — this
                    usually takes under a minute…
                  </p>
                  {pendingActions(pending)}
                </>
              )}
            </div>
          ) : (
            <>
              <label className="field stack">
                <span>Domain you own</span>
                <input
                  type="text"
                  value={input}
                  placeholder="yourname.com"
                  onInput={(e) =>
                    setInput((e.target as HTMLInputElement).value)
                  }
                />
              </label>
              <div className="popover-actions">
                <button
                  type="button"
                  disabled={busy || !input.trim()}
                  onClick={connect}
                >
                  Connect
                </button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

async function deriveKP(path: string, pw: string) {
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

export function App() {
  const priv = useSignal<Private>(createDefaultPrivate());
  const fetchSeq = useRef(0);
  // Set just before a rename moves `path`, so the path-change effect keeps the
  // editor open instead of bouncing back to the unlock screen.
  const renamingRef = useRef(false);

  const [working, setWorking] = useState<boolean>(false);
  const [pw, setPw] = useState<string>("");
  const [newPw, setNewPw] = useState<string>("");
  const [path, setPath] = useState<string>(
    decodeURIComponent(window.location.pathname.substring(1)),
  );
  const [pathIsNew, setPathIsNew] = useState<boolean>(false);
  const [setupComplete, setSetupComplete] = useState<boolean>(false);
  const [kp, setKP] = useState<SignKeyPair | null>(null);
  const [pwStatus, setPwStatus] = useState<boolean | undefined>(undefined);
  const [file, setFile] = useState<File | undefined>(undefined);
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [lastAdvancedType, setLastAdvancedType] = useState<Type>(Type.REDIR);
  const [toast, setToast] = useState<string>("");
  const [copied, setCopied] = useState<boolean>(false);
  const [shareOpen, setShareOpen] = useState<boolean>(false);
  const [justPublished, setJustPublished] = useState<boolean>(false);
  const [qrMode, setQrMode] = useState<"link" | "vcard">("link");
  const [shareDomain, setShareDomain] = useState<string | null>(null);
  const [renameTo, setRenameTo] = useState<string>("");
  const [deleteConfirm, setDeleteConfirm] = useState<string>("");

  const showError = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 6000);
  };

  const builderMode: BuilderMode =
    priv.value.type === Type.LINK_TREE ? "contact" : "advanced";
  const advancedType =
    priv.value.type === Type.LINK_TREE ? lastAdvancedType : priv.value.type;
  const tree = ensureLinkTree(priv.value.linkTree);
  const treeErrors =
    priv.value.type === Type.LINK_TREE ? linkTreeErrors(tree) : [];
  const validationErrors = useMemo(() => {
    if (priv.value.type === Type.LINK_TREE) {
      return treeErrors;
    }
    if (priv.value.type === Type.REDIR) {
      const target = normalizeUrl(priv.value.redir);
      if (!target) {
        return ["Enter a redirect destination before publishing."];
      }
      if (!URL.canParse(target)) {
        return ["Enter a valid redirect destination before publishing."];
      }
    }
    return [];
  }, [priv.value.type, priv.value.redir, treeErrors]);

  const pub = useMemo<Public | null>(() => {
    if (priv.value.type === Type.LINK_TREE) {
      return {
        html: linkTreeToHtml(
          ensureLinkTree(priv.value.linkTree),
          publicPageUrl(path.trim()),
        ),
      };
    }

    if (priv.value.type === Type.REDIR) {
      return { redir: normalizeUrl(priv.value.redir) };
    }

    if (priv.value.type === Type.BYTES && file) {
      return null;
    }

    let attrs: Record<string, any> = {};

    function preprocess(md: string): string {
      const { attributes, body } = fm(md);
      attrs = attributes as Record<string, any>;
      return body;
    }

    return {
      html:
        priv.value.type === Type.HTML_PAGE
          ? priv.value.html
          : intoDoc(
              marked.parse(priv.value.md, {
                pedantic: false,
                gfm: true,
                breaks: true,
                hooks: {
                  options: {},
                  preprocess,
                  postprocess: (html) => html,
                  processAllTokens: (x) => x,
                },
              }) as string,
              attrs,
            ),
    };
  }, [priv.value, file, path]);
  const url = publicPageUrl(path.trim());
  // Share artifacts (QR, printables, signature, copy/share) feature the chosen
  // address — a connected custom domain if one is picked, otherwise found.as.
  // The canonical found.as URL stays baked into the published page itself.
  const shareUrl = shareDomain ? `https://${shareDomain}/` : url;
  // Address without scheme, for display (the QR pill in the generated preview).
  const shareDisplay = shareDomain ?? `found.as/${path.trim()}`;
  const renameDiscouraged =
    renameTo.trim() !== "" && /[^a-z0-9/-]/.test(renameTo.trim());
  const qrVcard =
    priv.value.type === Type.LINK_TREE
      ? buildVcard(tree, shareUrl, false)
      : null;
  const signatureAvailable =
    priv.value.type === Type.LINK_TREE &&
    Boolean(tree.displayName.trim() || path.trim());
  const wideEditor =
    priv.value.type === Type.HTML_PAGE ||
    priv.value.type === Type.MARKDOWN_PAGE;
  const contactNeedsContent =
    priv.value.type === Type.LINK_TREE && !linkTreeHasPublishableContent(tree);
  const canPublish =
    !working &&
    pwStatus === true &&
    (priv.value.type !== Type.BYTES || Boolean(file)) &&
    !contactNeedsContent &&
    validationErrors.length === 0;

  useEffect(() => {
    window.history.replaceState(null, "", path ? `/${encodePath(path)}` : "/");
    if (renamingRef.current) {
      // A rename just moved the page; the new key derives from the same
      // password, so stay in the editor rather than re-prompting.
      renamingRef.current = false;
      return;
    }
    setSetupComplete(false);
    setStatusMessage("");
  }, [path]);

  useEffect(() => {
    let cancelled = false;
    setWorking(true);
    deriveKP(path, pw)
      .then((keyPair) => {
        if (!cancelled) {
          setKP(keyPair);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          showError(e.message);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setWorking(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [path, pw]);

  // The featured address (found.as or a connected custom domain) is chosen in
  // the Custom domains popover and drives the QR code, printables, signature
  // and generated preview. A different page can't inherit the previous choice.
  useEffect(() => {
    setShareDomain(null);
  }, [path, pw]);

  useEffect(() => {
    const currentFetch = ++fetchSeq.current;
    if (!kp) {
      return;
    }

    setWorking(true);
    const timeout = window.setTimeout(() => {
      fetchData(kp, path)
        .then((recvPriv) => {
          if (fetchSeq.current !== currentFetch) return;
          priv.value = recvPriv;
          setPwStatus(true);
          setPathIsNew(false);
        })
        .catch((e) => {
          if (fetchSeq.current !== currentFetch) return;
          if (e instanceof FourOFour) {
            priv.value = createDefaultPrivate();
            setPwStatus(true);
            setPathIsNew(true);
          } else if (e instanceof FourXX) {
            setPwStatus(false);
            setPathIsNew(false);
          } else if (e.name !== "AbortError") {
            showError(e.message);
          }
        })
        .finally(() => {
          if (fetchSeq.current === currentFetch) {
            setWorking(false);
          }
        });
    }, 200);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [path, kp]);

  useEffect(() => {
    if (priv.value.type !== Type.LINK_TREE) {
      setLastAdvancedType(priv.value.type);
    }
  }, [priv.value.type]);

  const setType = (type: Type) => {
    if (type !== Type.LINK_TREE) {
      setLastAdvancedType(type);
    }
    priv.value = {
      ...priv.value,
      type,
      linkTree:
        type === Type.LINK_TREE
          ? ensureLinkTree(priv.value.linkTree)
          : priv.value.linkTree,
    };
    setStatusMessage("");
  };

  const setBuilderMode = (mode: BuilderMode) => {
    setType(mode === "contact" ? Type.LINK_TREE : advancedType);
  };

  const copyPublicUrl = () => {
    navigator.clipboard
      .writeText(shareUrl)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1800);
      })
      .catch((e) => showError(e.message));
  };

  const canShare = typeof navigator.share === "function";

  const sharePublicUrl = () => {
    if (canShare) {
      navigator.share({ url: shareUrl }).catch(() => {});
    } else {
      copyPublicUrl();
    }
  };

  const vcardQrShown = qrMode === "vcard" && Boolean(qrVcard);

  const openPrintables = () => {
    const win = window.open("", "_blank");
    if (!win) {
      showError("Allow pop-ups to open the print page.");
      return;
    }
    win.document.write(printablesHtml(tree, shareUrl, shareDisplay));
    win.document.close();
  };

  const saveRecoveryKit = () => {
    const slug = path.trim().replace(/\//g, "-") || "found-as";
    downloadFile(
      `${slug}-recovery-kit.html`,
      new Blob([recoveryKitHtml(path.trim(), pw, url)], { type: "text/html" }),
    );
  };

  const saveQr = () => {
    const slug = path.trim().replace(/\//g, "-") || "found-as";
    try {
      if (vcardQrShown) {
        downloadQrPng(qrVcard!, `${slug}-contact-qr.png`);
      } else {
        downloadQrPng(shareUrl, `${slug}-found-as-qr.png`);
      }
    } catch (e) {
      showError((e as Error).message);
    }
  };

  const publish = async () => {
    if (!kp || !canPublish) {
      return;
    }
    setWorking(true);
    const privateValue =
      priv.value.type === Type.LINK_TREE
        ? {
            ...priv.value,
            linkTree: {
              ...tree,
              links: tree.links.map((link) => ({
                ...link,
                href: normalizeLink(link).href,
              })),
            },
          }
        : priv.value;

    try {
      let pubToSend = pub;
      if (priv.value.type === Type.LINK_TREE) {
        // The preview image rides the page's pub record as the `og`
        // subresource, served at <path>/og — one atomic publish.
        let ogUrl: string | undefined;
        let subs: Public["subs"];
        const wantAutoImage =
          (tree.social?.autoImage ?? true) &&
          !socialImageUrl(tree.social?.imageUrl);
        if (wantAutoImage) {
          try {
            const bytes = await renderOgImage(tree, shareDisplay);
            if (bytes) {
              subs = { og: { mime: "image/png", bytes } };
              const digest = new Uint8Array(
                await subtle.digest("SHA-256", bytes.slice()),
              );
              const version = Array.from(digest.slice(0, 4), (b) =>
                b.toString(16).padStart(2, "0"),
              ).join("");
              ogUrl = `${publicPageUrl(path.trim())}/og?v=${version}`;
            }
          } catch {
            showError(
              "Couldn't render the social preview image — publishing the page without it.",
            );
          }
        }
        pubToSend = {
          html: linkTreeToHtml(
            ensureLinkTree(privateValue.linkTree),
            url,
            ogUrl,
          ),
        };
        if (subs) {
          pubToSend.subs = subs;
        }
      } else if (pubToSend === null) {
        pubToSend = {
          bytes: new Uint8Array(await file!.arrayBuffer()),
          mime: file!.type,
        };
      }
      await updateData(kp, path, privateValue, pubToSend);
      setPathIsNew(false);
      setStatusMessage(
        `Your ${modeSummary(priv.value.type).toLowerCase()} is live.`,
      );
      setJustPublished(true);
      setShareOpen(true);
    } catch (e) {
      showError((e as Error).message);
    } finally {
      setWorking(false);
    }
  };

  if (!setupComplete || pwStatus !== true) {
    return (
      <main className="app-shell">
        <SetupPanel
          path={path}
          setPath={setPath}
          pw={pw}
          setPw={setPw}
          working={working}
          pwStatus={pwStatus}
          pathIsNew={pathIsNew}
          onContinue={() => {
            if (pathIsNew) {
              setType(Type.LINK_TREE);
            }
            setSetupComplete(true);
          }}
        />
      </main>
    );
  }

  return (
    <main className={`app-shell ${wideEditor ? "" : "app-shell-compact"}`}>
      <header className="topbar">
        <div className="topbar-id">
          <p className="eyebrow">Your public page</p>
          <a className="page-url" href={url} target="_blank" rel="noreferrer">
            <span className="page-url-prefix">found.as/</span>
            <span className="page-url-path">{path.trim()}</span>
          </a>
        </div>
        <div className="topbar-actions">
          {!pathIsNew && (
            <button
              type="button"
              className="secondary topbar-share"
              onClick={() => {
                setJustPublished(false);
                setShareOpen(true);
              }}
            >
              Share
            </button>
          )}
          <button
            type="button"
            className="secondary topbar-menu-button"
            popovertarget="topbarMenu"
          >
            Menu
          </button>
        </div>
      </header>

      <div popover="auto" id="topbarMenu" className="popover-panel topbar-menu">
        {signatureAvailable && (
          <button
            type="button"
            className="secondary"
            onClick={() => {
              document.getElementById("topbarMenu")?.hidePopover();
              document.getElementById("emailSignature")?.showPopover();
            }}
          >
            Email signature
          </button>
        )}
        {priv.value.type === Type.LINK_TREE && (
          <button
            type="button"
            className="secondary"
            onClick={() => {
              document.getElementById("topbarMenu")?.hidePopover();
              openPrintables();
            }}
          >
            Print cards &amp; poster
          </button>
        )}
        <button
          type="button"
          className="secondary"
          onClick={() => {
            document.getElementById("topbarMenu")?.hidePopover();
            document.getElementById("customDomain")?.showPopover();
          }}
        >
          Custom domains
        </button>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            document.getElementById("topbarMenu")?.hidePopover();
            saveRecoveryKit();
          }}
        >
          Save recovery kit
        </button>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            document.getElementById("topbarMenu")?.hidePopover();
            document.getElementById("changePw")?.showPopover();
          }}
        >
          Password
        </button>
        {!pathIsNew && (
          <>
            <hr className="menu-divider" />
            <button
              type="button"
              className="secondary"
              onClick={() => {
                document.getElementById("topbarMenu")?.hidePopover();
                setRenameTo("");
                document.getElementById("renamePage")?.showPopover();
              }}
            >
              Change address
            </button>
            <button
              type="button"
              className="secondary menu-danger"
              onClick={() => {
                document.getElementById("topbarMenu")?.hidePopover();
                setDeleteConfirm("");
                document.getElementById("deletePage")?.showPopover();
              }}
            >
              Delete page
            </button>
          </>
        )}
      </div>

      <section className="workspace workspace-compact">
        <div className="editor-panel">
          <BuilderModePicker
            mode={builderMode}
            setMode={setBuilderMode}
            advancedType={advancedType}
            setAdvancedType={setType}
          />

          {priv.value.type === Type.LINK_TREE ? (
            <LinkTreeEditor
              priv={priv}
              displayAddress={shareDisplay}
              onError={showError}
            />
          ) : priv.value.type === Type.REDIR ? (
            <RedirectEditor priv={priv} />
          ) : priv.value.type === Type.BYTES ? (
            <FileEditor file={file} setFile={setFile} onError={showError} />
          ) : pub !== null ? (
            <PageEditor priv={priv} pub={pub} />
          ) : null}
        </div>
      </section>

      {validationErrors.length > 0 && (
        <div className="notice error-box" role="alert">
          {validationErrors.map((error) => (
            <p key={error}>{error}</p>
          ))}
        </div>
      )}

      <footer className="publish-bar">
        <div aria-live="polite">
          {statusMessage ||
            (working
              ? "Working..."
              : contactNeedsContent
                ? "Add a name, photo, description, or link."
                : "Ready to publish.")}
        </div>
        <div className="publish-actions">
          <button type="button" disabled={!canPublish} onClick={publish}>
            {publishLabel(priv.value.type)}
          </button>
        </div>
      </footer>

      <div
        popover="auto"
        id="changePw"
        className="popover-panel password-popover"
      >
        <div className="popover-heading">
          <h2>Update password</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={() => document.getElementById("changePw")?.hidePopover()}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <label className="field stack">
          <span>New password</span>
          <input
            type="password"
            value={newPw}
            onInput={(e) => setNewPw((e.target as HTMLInputElement).value)}
          />
        </label>
        <div className="popover-actions">
          <button
            type="button"
            onClick={() => {
              if (!kp) {
                return;
              }
              setWorking(true);
              updatePw(kp, path, newPw)
                .then(() => {
                  setPw(newPw);
                  setNewPw("");
                  setStatusMessage(
                    "Password changed — save a fresh recovery kit.",
                  );
                  document.getElementById("changePw")?.hidePopover();
                })
                .catch((e) => {
                  showError(e.message);
                })
                .finally(() => {
                  setWorking(false);
                });
            }}
          >
            Save
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => document.getElementById("changePw")?.hidePopover()}
          >
            Cancel
          </button>
        </div>
      </div>

      <div popover="auto" id="renamePage" className="popover-panel">
        <div className="popover-heading">
          <h2>Change address</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={() => document.getElementById("renamePage")?.hidePopover()}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <label className="field stack">
          <span>New address</span>
          <span className="path-field">
            <span className="path-prefix">found.as/</span>
            <input
              type="text"
              aria-label="New page path"
              maxLength={64}
              value={renameTo}
              autoComplete="off"
              autoCapitalize="off"
              spellcheck={false}
              placeholder={path.trim()}
              onInput={(e) => setRenameTo((e.target as HTMLInputElement).value)}
            />
          </span>
        </label>
        {renameDiscouraged && (
          <p className="help warning-text">
            Lowercase letters, numbers and hyphens make the best address —
            capitals and special characters are harder to type and share.
          </p>
        )}
        <p className="help">
          Your page moves to the new address. The old one stops working, and any
          custom domains follow automatically.
        </p>
        <div className="popover-actions">
          <button
            type="button"
            disabled={
              working ||
              !renameTo.trim() ||
              renameTo.trim() === path.trim()
            }
            onClick={() => {
              if (!kp) {
                return;
              }
              const target = renameTo.trim();
              setWorking(true);
              renamePage(kp, path, target, pw)
                .then(() => {
                  document.getElementById("renamePage")?.hidePopover();
                  setPathIsNew(false);
                  renamingRef.current = true;
                  setPath(target);
                  setStatusMessage(`Now at found.as/${target}.`);
                })
                .catch((e) => showError(e.message))
                .finally(() => setWorking(false));
            }}
          >
            Move page
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => document.getElementById("renamePage")?.hidePopover()}
          >
            Cancel
          </button>
        </div>
      </div>

      <div popover="auto" id="deletePage" className="popover-panel">
        <div className="popover-heading">
          <h2>Delete page</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={() => document.getElementById("deletePage")?.hidePopover()}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <p className="help warning-text">
          This permanently removes found.as/{path.trim()} and releases any custom
          domains. There's no undo.
        </p>
        <label className="field stack">
          <span>
            Type <strong>{path.trim()}</strong> to confirm
          </span>
          <input
            type="text"
            autoComplete="off"
            autoCapitalize="off"
            spellcheck={false}
            value={deleteConfirm}
            onInput={(e) =>
              setDeleteConfirm((e.target as HTMLInputElement).value)
            }
          />
        </label>
        <div className="popover-actions">
          <button
            type="button"
            disabled={working || deleteConfirm.trim() !== path.trim()}
            onClick={() => {
              if (!kp) {
                return;
              }
              setWorking(true);
              deletePage(kp, path)
                .then(() => {
                  window.location.href = "https://be.found.as/";
                })
                .catch((e) => {
                  showError(e.message);
                  setWorking(false);
                });
            }}
          >
            Delete permanently
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => document.getElementById("deletePage")?.hidePopover()}
          >
            Cancel
          </button>
        </div>
      </div>

      {kp && (
        <DomainPopover
          kp={kp}
          path={path.trim()}
          shareDomain={shareDomain}
          setShareDomain={setShareDomain}
          onError={showError}
        />
      )}

      {signatureAvailable && !shareOpen && (
        <EmailSignaturePopover tree={tree} url={shareUrl} onError={showError} />
      )}

      {shareOpen && (
        <div
          className="publish-success-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="publish-success-title"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShareOpen(false);
          }}
        >
          <div className="publish-success">
            <div className="popover-heading">
              <h2 id="publish-success-title">
                {justPublished ? "You're live 🎉" : "Share your page"}
              </h2>
              <button
                type="button"
                className="icon-button"
                aria-label="Close"
                onClick={() => setShareOpen(false)}
              >
                <span aria-hidden="true">×</span>
              </button>
            </div>
            <button
              type="button"
              className="qr-frame"
              onClick={saveQr}
              title="Save QR code"
            >
              <QrCode value={vcardQrShown ? qrVcard! : shareUrl} />
            </button>
            {qrVcard && (
              <div className="qr-mode" role="group" aria-label="QR code type">
                <button
                  type="button"
                  className="secondary"
                  aria-pressed={!vcardQrShown}
                  onClick={() => setQrMode("link")}
                >
                  Page link
                </button>
                <button
                  type="button"
                  className="secondary"
                  aria-pressed={vcardQrShown}
                  onClick={() => setQrMode("vcard")}
                >
                  Contact card
                </button>
              </div>
            )}
            {vcardQrShown && (
              <p className="help qr-mode-help">
                Scanning saves your contact card directly — even without
                internet.
              </p>
            )}
            <a
              className="success-url"
              href={shareUrl}
              target="_blank"
              rel="noreferrer"
            >
              {shareUrl}
            </a>
            <div className="success-actions">
              <button type="button" onClick={sharePublicUrl} aria-live="polite">
                {canShare ? "Share" : copied ? "Copied ✓" : "Copy link"}
              </button>
              <button type="button" className="secondary" onClick={saveQr}>
                Save QR
              </button>
              <button
                type="button"
                className="secondary"
                onClick={saveRecoveryKit}
              >
                Save recovery kit
              </button>
              {signatureAvailable && (
                <button
                  type="button"
                  className="secondary"
                  popovertarget="emailSignature"
                >
                  Email signature
                </button>
              )}
              {priv.value.type === Type.LINK_TREE && (
                <button
                  type="button"
                  className="secondary"
                  onClick={openPrintables}
                >
                  Print cards &amp; poster
                </button>
              )}
              <a
                className="button-link secondary"
                href={shareUrl}
                target="_blank"
                rel="noreferrer"
              >
                Open
              </a>
            </div>
            {signatureAvailable && (
              <EmailSignaturePopover
                tree={tree}
                url={shareUrl}
                onError={showError}
              />
            )}
          </div>
        </div>
      )}

      {toast && (
        <div className="toast" role="alert" onClick={() => setToast("")}>
          {toast}
        </div>
      )}
    </main>
  );
}
