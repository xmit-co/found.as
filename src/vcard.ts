import { activeValidLinks } from "./linktree";
import { avatarImageSrc } from "./theme";
import { LinkTree } from "./types";

export function escapeVcardValue(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r\n|\r|\n/g, "\\n");
}

export function vcardUriValue(value: string): string {
  return value.replace(/[\r\n]/g, "");
}

export function utf8Octets(codePoint: number): number {
  if (codePoint < 0x80) return 1;
  if (codePoint < 0x800) return 2;
  if (codePoint < 0x10000) return 3;
  return 4;
}

export function foldVcardLine(line: string): string {
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

export function vcardNameLine(displayName: string): string {
  const parts = displayName.trim().split(/\s+/);
  const family = parts.length > 1 ? parts[parts.length - 1] : "";
  const given = parts.length > 1 ? parts.slice(0, -1).join(" ") : parts[0];
  return `N:${escapeVcardValue(family)};${escapeVcardValue(given)};;;`;
}

export function vcardPhotoLine(avatarUrl: string | undefined): string | null {
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

export function vcardFileName(displayName: string): string {
  const base = displayName
    .trim()
    .replace(/[\\/:*?"<>|]+/g, "")
    .trim();
  return `${base || "contact"}.vcf`;
}

export function vcardEligible(tree: LinkTree): boolean {
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

export function buildVcard(
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
