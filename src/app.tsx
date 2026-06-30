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
  | "address"
  | "custom";

interface LinkItem {
  id: string;
  kind: LinkKind;
  label: string;
  value: string;
  href: string;
  enabled: boolean;
}

interface LinkTree {
  displayName: string;
  bio: string;
  avatarUrl?: string;
  theme: "system" | "light" | "dark" | "warm" | "clean";
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
  address: "Address",
  custom: "Custom link",
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
  address: "1 Rue de Rivoli, Paris",
  custom: "https://example.com",
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
  address: "",
  custom: "https://",
};

function makeId(): string {
  if (window.crypto.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function defaultLinkItem(kind: LinkKind): LinkItem {
  return {
    id: makeId(),
    kind,
    label: kindLabels[kind],
    value: kindDefaultValues[kind],
    href: "",
    enabled: true,
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
    return { href: "", error: "Finish the Instagram URL or username." };
  }
  const username =
    valueFromKnownHost(value, ["instagram.com"]) ??
    normalizeSocialUsername(value);
  if (!username) {
    return { href: "", error: "Enter an Instagram username or URL." };
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
    return { href: "", error: `Enter a ${service} username or URL.` };
  }
  if (trimmed.includes(".") || trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    if (!URL.canParse(normalized)) {
      return { href: "", error: `Enter a valid ${service} URL.` };
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
    return { href: "", error: "Enter a Bluesky handle or URL." };
  }
  if (trimmed.includes("://")) {
    return URL.canParse(trimmed)
      ? { href: trimmed }
      : { href: "", error: "Enter a valid Bluesky URL." };
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
    return { href: "", error: "Enter a Mastodon address or URL." };
  }
  if (trimmed.includes("://")) {
    return URL.canParse(trimmed)
      ? { href: trimmed }
      : { href: "", error: "Enter a valid Mastodon URL." };
  }
  const [user, host] = trimmed.replace(/^@+/, "").split("@");
  if (user && host) {
    return { href: `https://${host}/@${encodeURIComponent(user)}` };
  }
  return {
    href: "",
    error: "Use @you@server, or paste your profile URL.",
  };
}

function normalizeMatrix(value: string): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter a Matrix ID or URL." };
  }
  if (trimmed.includes("://")) {
    return URL.canParse(trimmed)
      ? { href: trimmed }
      : { href: "", error: "Enter a valid Matrix URL." };
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

function normalizeMap(value: string): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter an address or map URL." };
  }
  if (trimmed.includes("://")) {
    if (!URL.canParse(trimmed)) {
      return { href: "", error: "Enter a valid map URL." };
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
    return { href: "", error: `Finish the ${label.toLowerCase()} URL.` };
  }
  const normalized = normalizeUrl(value);
  if (!normalized) {
    return { href: "", error: `Enter a ${label.toLowerCase()} URL.` };
  }
  if (!URL.canParse(normalized)) {
    return { href: "", error: `Enter a valid ${label.toLowerCase()} URL.` };
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

function normalizeLink(item: LinkItem): NormalizedLink {
  const label = item.label.trim() || kindLabels[item.kind];
  const value = item.value.trim();
  if (!item.enabled || !value) {
    return { item, label, href: "" };
  }

  return { item, label, ...normalizeByKind(item.kind, value, label) };
}

function normalizedLinks(tree: LinkTree): NormalizedLink[] {
  return tree.links.map(normalizeLink);
}

function isDefaultLinkValue(link: LinkItem): boolean {
  const value = link.value.trim().replace(/\/$/, "");
  const defaultValue = kindDefaultValues[link.kind].trim().replace(/\/$/, "");
  return Boolean(defaultValue) && value === defaultValue;
}

function activeValidLinks(tree: LinkTree): NormalizedLink[] {
  return normalizedLinks(tree).filter((link) => link.href && !link.error);
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
  return normalizedLinks(tree)
    .filter(
      (link) =>
        link.error &&
        link.item.enabled &&
        link.item.value.trim() &&
        !isDefaultLinkValue(link.item),
    )
    .map((link) => `${link.label}: ${link.error}`);
}

function linkTreeToHtml(tree: LinkTree): string {
  const safeName = tree.displayName.trim() || "Contact";
  const safeBio = tree.bio.trim();
  const avatar = avatarImageSrc(tree.avatarUrl);
  const links = activeValidLinks(tree);
  const themeClass = `theme-${tree.theme || "system"}`;

  return `<!DOCTYPE html>
<html lang="en" class="${themeClass}">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<meta name="description" content="${escapeHtml(safeBio || `${safeName} on found.as`)}"/>
<title>${escapeHtml(safeName)}</title>
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
.theme-warm {
  --bg: #fbf8f0;
  --text: #221b13;
  --muted: #665b4c;
  --panel: #ffffff;
  --border: #ddd2c1;
  --accent: #9a4f24;
}
.theme-clean {
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
* { box-sizing: border-box; }
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
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
  color: var(--text);
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
    links.length
      ? `<nav aria-label="Contact links">
    ${links
      .map(
        (link) =>
          `<a class="contact-link" href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>`,
      )
      .join("\n    ")}
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
        {valid ? normalizedUrl : "Enter a valid destination URL."}
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
];

function linkValueLabel(kind: LinkKind): string {
  if (kind === "phone" || kind === "whatsapp") return "Number";
  if (kind === "email") return "Email address";
  if (kind === "address") return "Address or map URL";
  if (kind === "mastodon" || kind === "matrix" || kind === "bluesky") {
    return "Handle or URL";
  }
  if (handleKinds.includes(kind)) return "Username or URL";
  return "URL";
}

function EditableLink({
  link,
  index,
  total,
  updateLink,
  removeLink,
  moveTo,
  moveBy,
  dragging,
  setDragging,
  dropTarget,
  setDragOver,
  selected,
  setSelected,
}: {
  link: LinkItem;
  index: number;
  total: number;
  updateLink: (link: LinkItem) => void;
  removeLink: () => void;
  moveTo: (draggedId: string, targetId: string) => void;
  moveBy: (id: string, delta: number) => void;
  dragging: boolean;
  setDragging: (id: string) => void;
  dropTarget: boolean;
  setDragOver: (id: string) => void;
  selected: boolean;
  setSelected: (id: string) => void;
}) {
  const normalized = normalizeLink(link);
  const fieldId = `link-${link.id}`;
  const detailId = `${fieldId}-detail`;
  const valueLabel = linkValueLabel(link.kind);
  const label = link.label.trim() || kindLabels[link.kind];
  const optionalIncomplete = Boolean(
    normalized.error && isDefaultLinkValue(link),
  );

  return (
    <article
      className={`editable-link ${selected ? "is-selected" : ""} ${dragging ? "is-dragging" : ""} ${dropTarget ? "is-drop-target" : ""} ${link.enabled ? "" : "is-disabled"}`}
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
            <span>Button text</span>
            <input
              type="text"
              value={link.label}
              placeholder={kindLabels[link.kind]}
              onInput={(e) =>
                updateLink({
                  ...link,
                  label: (e.target as HTMLInputElement).value,
                })
              }
            />
          </label>
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
          {link.kind === "email" && (
            <p className="help">
              Need a public email address? Create a forwarding alias at{" "}
              <a href="https://cc.me/hi" target="_blank" rel="noreferrer">
                cc.me/hi
              </a>
              .
            </p>
          )}
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
              (normalized.href ? normalized.href : "Hidden until complete.")}
          </p>
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
  onError,
}: {
  priv: Signal<Private>;
  onError: (message: string) => void;
}) {
  const tree = ensureLinkTree(priv.value.linkTree);
  const [draggingId, setDraggingId] = useState("");
  const [dragOverId, setDragOverId] = useState("");
  const [selectedLinkId, setSelectedLinkId] = useState("");

  const updateTree = (nextTree: LinkTree) => {
    priv.value = {
      ...priv.value,
      type: Type.LINK_TREE,
      linkTree: nextTree,
    };
  };

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
      <div className={`live-page theme-${tree.theme || "system"}`}>
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
                removeLink={() => removeLink(link.id)}
                moveTo={moveLinkTo}
                moveBy={moveLinkBy}
                dragging={draggingId === link.id}
                setDragging={setDraggingId}
                dropTarget={dragOverId === link.id && draggingId !== link.id}
                setDragOver={setDragOverId}
                selected={selectedLinkId === link.id}
                setSelected={setSelectedLinkId}
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
      </fieldset>
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
        <h2 id="intent-title">Choose how this found.as page works</h2>
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
      description: "Send visitors to one destination URL.",
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
          <span>Page URL</span>
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
          There is no password reset. Your address and password are the only
          keys to this page — save them somewhere safe.
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
  const [published, setPublished] = useState<boolean>(false);

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
        html: linkTreeToHtml(ensureLinkTree(priv.value.linkTree)),
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
      .writeText(url)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1800);
      })
      .catch((e) => showError(e.message));
  };

  const canShare = typeof navigator.share === "function";

  const sharePublicUrl = () => {
    if (canShare) {
      navigator.share({ url }).catch(() => {});
    } else {
      copyPublicUrl();
    }
  };

  const saveQr = () => {
    const slug = path.trim().replace(/\//g, "-") || "found-as";
    try {
      downloadQrPng(url, `${slug}-found-as-qr.png`);
    } catch (e) {
      showError((e as Error).message);
    }
  };

  const publish = () => {
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

    (pub !== null
      ? updateData(kp, path, privateValue, pub)
      : (async () =>
          updateData(kp, path, privateValue, {
            bytes: new Uint8Array(await file!.arrayBuffer()),
            mime: file!.type,
          }))()
    )
      .then(() => {
        setPathIsNew(false);
        setStatusMessage(
          `Your ${modeSummary(priv.value.type).toLowerCase()} is live.`,
        );
        setPublished(true);
      })
      .catch((e) => {
        showError(e.message);
      })
      .finally(() => {
        setWorking(false);
      });
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
          <button
            type="button"
            className="secondary"
            onClick={copyPublicUrl}
            aria-live="polite"
          >
            {copied ? "Copied ✓" : "Copy link"}
          </button>
          <a
            className="button-link secondary"
            href={url}
            target="_blank"
            rel="noreferrer"
          >
            Open
          </a>
          <button type="button" className="secondary" popovertarget="changePw">
            Password
          </button>
        </div>
      </header>

      <section className="workspace workspace-compact">
        <div className="editor-panel">
          <BuilderModePicker
            mode={builderMode}
            setMode={setBuilderMode}
            advancedType={advancedType}
            setAdvancedType={setType}
          />

          {priv.value.type === Type.LINK_TREE ? (
            <LinkTreeEditor priv={priv} onError={showError} />
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
                  setStatusMessage("Update password changed.");
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

      {published && (
        <div
          className="publish-success-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="publish-success-title"
          onClick={(e) => {
            if (e.target === e.currentTarget) setPublished(false);
          }}
        >
          <div className="publish-success">
            <div className="popover-heading">
              <h2 id="publish-success-title">You're live 🎉</h2>
              <button
                type="button"
                className="icon-button"
                aria-label="Close"
                onClick={() => setPublished(false)}
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
              <QrCode value={url} />
            </button>
            <a
              className="success-url"
              href={url}
              target="_blank"
              rel="noreferrer"
            >
              {url}
            </a>
            <div className="success-actions">
              <button type="button" onClick={sharePublicUrl}>
                {canShare ? "Share" : "Copy link"}
              </button>
              <button type="button" className="secondary" onClick={saveQr}>
                Save QR
              </button>
              <button
                type="button"
                className="secondary"
                onClick={copyPublicUrl}
              >
                {copied ? "Copied ✓" : "Copy link"}
              </button>
              <a
                className="button-link secondary"
                href={url}
                target="_blank"
                rel="noreferrer"
              >
                Open
              </a>
            </div>
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
