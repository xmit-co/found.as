import {
  accentDarkText,
  accentLightText,
  accentPair,
  printAccents,
} from "./color";
import {
  activeValidLinks,
  featuredLink,
  isBlock,
  linkTreeListedEntries,
  renderTextBlockMarkdown,
} from "./linktree";
import { qrSvgString } from "./qr";
import {
  avatarImageSrc,
  avatarRadius,
  clampBtnAlpha,
  clampBtnBlur,
  clampCoverHeight,
  clampLighten,
  clampShade,
  clampZoom,
  cornerRadius,
  fontStack,
  linkIconEmoji,
  linkIconSrc,
  pageBackground,
  sanitizeObjectPosition,
} from "./theme";
import {
  LinkTree,
  NormalizedLink,
  identityKinds,
  kindDefaultIcons,
} from "./types";
import { encodePath, escapeHtml } from "./util";
import { buildVcard, vcardFileName } from "./vcard";

export function signatureAvatarSrc(value: string | undefined): string | null {
  const src = avatarImageSrc(value);
  if (!src || !/^https:\/\//i.test(src)) return null;
  return src;
}

export function signatureHtml(tree: LinkTree, url: string): string {
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

export function signatureText(tree: LinkTree, url: string): string {
  return [tree.displayName.trim(), tree.bio.trim(), url]
    .filter(Boolean)
    .join("\n");
}

export async function copyRichSignature(
  html: string,
  text: string,
): Promise<boolean> {
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

export function intoDoc(fragment: string, attrs: Record<string, any>) {
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

// Structured profile for the published page, surfaced by the IndieAuth
// profile/email scopes: name, avatar photo, and the chosen email. The profile
// URL is added by the backend (the identity that signed in).
export function linkTreeProfile(tree: LinkTree): {
  name?: string;
  photo?: string;
  email?: string;
} {
  const profile: { name?: string; photo?: string; email?: string } = {};
  const name = tree.displayName.trim();
  if (name) profile.name = name;
  const photo = avatarImageSrc(tree.avatarUrl);
  if (photo) profile.photo = photo;
  // Among the shown email links, honour the owner's pick (by id); with one
  // email that's simply it, with none there's no email to share.
  const emails = activeValidLinks(tree).filter((l) => l.item.kind === "email");
  const chosen =
    emails.find((l) => l.item.id === tree.profileEmailId) ?? emails[0];
  if (chosen) {
    const email = chosen.href
      .replace(/^mailto:/i, "")
      .split("?")[0]
      .trim();
    if (email) profile.email = email;
  }
  return profile;
}

export function linkTreeToHtml(
  tree: LinkTree,
  url: string,
  generatedOgUrl?: string,
  bgLightUrl?: string,
  bgDarkUrl?: string,
): string {
  const safeName = tree.displayName.trim() || "Contact";
  const safeBio = tree.bio.trim();
  const avatar = avatarImageSrc(tree.avatarUrl);
  const metaTitle = tree.social?.title?.trim() || safeName;
  const metaDescription =
    tree.social?.description?.trim() || safeBio || `${safeName} on found.as`;
  const ogImage = generatedOgUrl;
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
  // Web links open in a new tab — the norm for a link hub, and it keeps
  // embeds (like the landing page's phone previews) from navigating inside
  // their frame. tel:/mailto: don't navigate the page and get no target.
  const linkRelAttr = (link: NormalizedLink) => {
    const me =
      identityKinds.has(link.item.kind) &&
      link.item.relMe !== false &&
      /^(https?:|mailto:|tel:|sms:)/i.test(link.href);
    const blank = /^https?:/i.test(link.href);
    const rel = [me ? "me" : "", blank ? "noopener" : ""]
      .filter(Boolean)
      .join(" ");
    return `${rel ? ` rel="${rel}"` : ""}${blank ? ' target="_blank"' : ""}`;
  };
  const linkInner = (link: NormalizedLink) => {
    const badge = link.item.badge?.trim();
    const desc = link.item.desc?.trim();
    return `${linkIconHtml(link)}<span class="link-label">${escapeHtml(link.label)}</span>${
      badge ? `<span class="link-badge">${escapeHtml(badge)}</span>` : ""
    }${desc ? `<span class="link-desc">${escapeHtml(desc)}</span>` : ""}`;
  };

  const font = fontStack(tree);
  const radius = cornerRadius(tree);
  const avatarRad = avatarRadius(tree);
  // Custom background image, served as a sub and shown as uploaded. The
  // lighten/darken treatments are CSS overlay layers, not baked into the
  // image: light themes lay white at bgLighten% over it; dark ones swap in
  // the custom dark image if there is one, and lay black at bgShade% over it.
  const bgImage = tree.background === "image" && bgLightUrl;
  const overlay = (rgb: string, alpha: number) =>
    alpha > 0
      ? `linear-gradient(rgb(${rgb} / ${alpha}), rgb(${rgb} / ${alpha})), `
      : "";
  const bgImg = (u: string, ov = "") =>
    `${ov}url("${escapeHtml(u)}") center / cover no-repeat fixed, var(--bg)`;
  const bgLight = bgImage
    ? bgImg(
        bgLightUrl!,
        overlay("255 255 255", clampLighten(tree.bgLighten) / 100),
      )
    : "";
  const bgDark = bgImage
    ? bgImg(
        bgDarkUrl ?? bgLightUrl!,
        overlay("0 0 0", clampShade(tree.bgShade) / 100),
      )
    : "";
  const bg = bgImage
    ? tree.theme === "dark"
      ? bgDark
      : bgLight
    : pageBackground(tree);
  const bgDarkCss =
    bgImage && tree.theme === "system"
      ? `@media (prefers-color-scheme: dark) {\n  html.theme-system body { background: ${bgDark}; }\n}\n`
      : "";
  const buttons = tree.buttons ?? "soft";
  // Glassy buttons: a semi-transparent surface (per the chosen style) and a
  // backdrop blur, emitted only when set so plain pages stay plain.
  const btnAlpha = clampBtnAlpha(tree.btnAlpha);
  const btnBlur = clampBtnBlur(tree.btnBlur);
  const btnSurface =
    buttons === "filled"
      ? "var(--accent)"
      : buttons === "outline"
        ? "transparent"
        : "color-mix(in srgb, var(--accent) 7%, var(--panel))";
  const btnFx =
    btnAlpha < 100 || btnBlur > 0
      ? `${
          btnBlur > 0
            ? `a.contact-link,
a.vcard-button {
  -webkit-backdrop-filter: blur(${btnBlur}px);
  backdrop-filter: blur(${btnBlur}px);
}
`
            : ""
        }${
          btnAlpha < 100
            ? `a.contact-link:not(.featured) {
  background: color-mix(in srgb, ${btnSurface} ${btnAlpha}%, transparent);
}
a.contact-link.featured {
  background: color-mix(in srgb, var(--accent) ${btnAlpha}%, transparent);
}
`
            : ""
        }`
      : "";
  const cover = avatarImageSrc(tree.coverUrl);
  const coverObjectFit = tree.coverFit === "contain" ? "contain" : "cover";
  const coverObjectPos = sanitizeObjectPosition(tree.coverPos);
  const coverHeight = clampCoverHeight(tree.coverHeight);
  const coverZoom = clampZoom(tree.coverZoom);
  const avatarObjectPos = sanitizeObjectPosition(tree.avatarPos);
  const avatarZoom = clampZoom(tree.avatarZoom);
  const coverIsTitle = Boolean(cover) && Boolean(tree.coverTitle);
  const status = tree.status?.trim();
  const favicon = linkIconEmoji(tree.favicon);
  const faviconLink = favicon
    ? `<link rel="icon" href="data:image/svg+xml,${encodeURIComponent(
        `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><text x='16' y='25' font-size='28' text-anchor='middle'>${favicon}</text></svg>`,
      )}"/>\n`
    : "";
  const htmlClass = `${themeClass} btn-${buttons}${cover ? " has-cover" : ""}${coverIsTitle ? " cover-title" : ""}`;

  return `<!DOCTYPE html>
<html lang="en" class="${htmlClass}">
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
${faviconLink}<link rel="authorization_endpoint" href="https://be.found.as/indieauth"/>
<link rel="indieauth-metadata" href="https://be.found.as/.well-known/oauth-authorization-server"/>
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
  --radius: ${radius};
  --avatar-radius: ${avatarRad};
  font-family: ${font};
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
${accentCss}${bgDarkCss}* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100svh;
  display: grid;
  place-items: center;
  padding: 1.5rem;
  background: ${bg};
  background-attachment: fixed;
  color: var(--text);
}
main {
  width: min(100%, 27.5rem);
}
.cover {
  width: 100%;
  ${coverObjectFit === "contain" ? "" : `aspect-ratio: 440 / ${coverHeight};`}
  border-radius: var(--radius);
  overflow: hidden;
  margin-bottom: 1rem;
}
.cover img {
  width: 100%;
  display: block;
  ${
    coverObjectFit === "contain"
      ? "height: auto;"
      : `height: 100%; object-fit: cover; object-position: ${coverObjectPos}; transform: scale(${coverZoom}); transform-origin: ${coverObjectPos};`
  }
}
.profile {
  text-align: center;
  margin-bottom: 1.5rem;
}
.avatar {
  width: 5.5rem;
  height: 5.5rem;
  border-radius: var(--avatar-radius);
  border: 1px solid var(--border);
  background: var(--panel);
  display: inline-grid;
  place-items: center;
  margin-bottom: 1rem;
  overflow: hidden;
  color: var(--accent);
  font-size: 1.75rem;
  font-weight: 700;
}
.has-cover .avatar {
  margin-top: -3.75rem;
  box-shadow: 0 0 0 4px var(--bg);
}
.cover-title h1 {
  position: absolute;
  width: 0.0625rem;
  height: 0.0625rem;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  clip-path: inset(50%);
  white-space: nowrap;
}
.status {
  display: inline-block;
  margin: 0.75rem 0 0;
  padding: 0.25rem 0.75rem;
  border-radius: 999px;
  font-size: 0.85rem;
  font-weight: 650;
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 12%, var(--panel));
}
.avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: ${avatarObjectPos};
  transform: scale(${avatarZoom});
  transform-origin: ${avatarObjectPos};
}
h1 {
  margin: 0;
  font-size: clamp(2rem, 9vw, 3rem);
  line-height: 1;
  letter-spacing: 0;
  font-weight: 800;
}
p {
  margin: 0.75rem 0 0;
  color: var(--text);
  font-size: 1rem;
  line-height: 1.5;
}
nav {
  display: grid;
  gap: 0.625rem;
}
a.contact-link {
  min-height: 3rem;
  display: block;
  align-content: center;
  padding: 0.75rem 1rem;
  border: 1px solid color-mix(in srgb, var(--accent) 45%, var(--border));
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--accent) 7%, var(--panel));
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
  min-height: 2.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 0 1rem;
  padding: 0.625rem 1rem;
  border: 1px solid var(--accent);
  border-radius: var(--radius);
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
  margin: 0.875rem 0 0;
  font-size: 0.82rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  text-align: center;
  /* Full-contrast text: muted gray washes out on colorful backgrounds. */
  color: var(--text);
}
h2.link-section:first-child {
  margin-top: 0;
}
img.link-icon {
  width: 1.25rem;
  height: 1.25rem;
  border-radius: 0.25rem;
  margin-right: 0.625rem;
  vertical-align: -4px;
}
span.link-icon-emoji {
  margin-right: 0.625rem;
}
.link-badge {
  display: inline-block;
  margin-left: 0.5rem;
  padding: 0.0625rem 0.5rem;
  border-radius: 999px;
  font-size: 0.72rem;
  font-weight: 700;
  vertical-align: 1px;
  background: color-mix(in srgb, var(--accent) 16%, var(--panel));
  color: var(--accent);
}
.link-desc {
  display: block;
  margin-top: 0.1875rem;
  font-size: 0.82rem;
  font-weight: 500;
  color: var(--muted);
}
.contact-link.featured .link-badge {
  background: color-mix(in srgb, var(--accent-text) 22%, transparent);
  color: var(--accent-text);
}
.contact-link.featured .link-desc {
  color: color-mix(in srgb, var(--accent-text) 80%, transparent);
}
.btn-outline a.contact-link:not(.featured) {
  background: transparent;
  border-color: var(--accent);
}
.btn-filled a.contact-link:not(.featured) {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--accent-text);
}
.btn-filled a.contact-link:not(.featured):hover {
  background: color-mix(in srgb, var(--accent) 85%, var(--text));
  border-color: color-mix(in srgb, var(--accent) 85%, var(--text));
}
.btn-filled a.contact-link:not(.featured) .link-desc {
  color: color-mix(in srgb, var(--accent-text) 80%, transparent);
}
.btn-filled a.contact-link:not(.featured) .link-badge {
  background: color-mix(in srgb, var(--accent-text) 22%, transparent);
  color: var(--accent-text);
}
p.link-text {
  margin: 0;
  padding: 0.125rem 0.25rem;
  color: var(--text);
  font-size: 0.95rem;
  line-height: 1.55;
  white-space: pre-line;
  text-align: center;
}
.link-text.md {
  padding: 0.125rem 0.25rem;
  color: var(--text);
  font-size: 0.95rem;
  line-height: 1.55;
  text-align: left;
}
.link-text.md > :first-child { margin-top: 0; }
.link-text.md > :last-child { margin-bottom: 0; }
.link-text.md p { margin: 0 0 0.6em; }
.link-text.md ul, .link-text.md ol { margin: 0 0 0.6em; padding-left: 1.35em; }
.link-text.md li { margin: 0.15em 0; }
.link-text.md h1, .link-text.md h2, .link-text.md h3,
.link-text.md h4, .link-text.md h5, .link-text.md h6 {
  margin: 0.4em 0 0.3em;
  line-height: 1.25;
}
.link-text.md h1 { font-size: 1.3rem; }
.link-text.md h2 { font-size: 1.15rem; }
.link-text.md h3 { font-size: 1.02rem; }
.link-text.md a { color: var(--accent); }
.link-text.md code {
  font-size: 0.88em;
  padding: 0.1em 0.35em;
  border-radius: 0.3125rem;
  background: color-mix(in srgb, var(--text) 9%, transparent);
}
.link-text.md pre {
  margin: 0 0 0.6em;
  padding: 0.625rem 0.75rem;
  border-radius: 0.5rem;
  overflow-x: auto;
  background: color-mix(in srgb, var(--text) 8%, transparent);
}
.link-text.md pre code { padding: 0; background: none; }
.link-text.md blockquote {
  margin: 0 0 0.6em;
  padding: 0.1em 0 0.1em 0.8em;
  border-left: 3px solid color-mix(in srgb, var(--text) 22%, transparent);
  color: var(--muted);
}
.link-text.md hr {
  border: 0;
  border-top: 1px solid color-mix(in srgb, var(--text) 15%, transparent);
  margin: 0.7em 0;
}
.link-text.md img { max-width: 100%; height: auto; border-radius: 8px; }
${btnFx}</style>
</head>
<body>
<main>
  ${cover ? `<div class="cover"${coverIsTitle ? "" : ' aria-hidden="true"'}><img src="${escapeHtml(cover)}" alt="${coverIsTitle ? escapeHtml(safeName) : ""}"/></div>` : ""}
  <section class="profile" aria-labelledby="profile-title">
    ${avatar ? `<div class="avatar" aria-hidden="true"><img src="${escapeHtml(avatar)}" alt=""/></div>` : ""}
    <h1 id="profile-title">${escapeHtml(safeName)}</h1>
    ${status ? `<p class="status">${escapeHtml(status)}</p>` : ""}
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
            `<a class="contact-link featured" href="${escapeHtml(featured.href)}"${linkRelAttr(featured)}>${linkInner(featured)}</a>`,
          ]
        : []),
      ...entries.map((entry) =>
        entry.kind === "section"
          ? `<h2 class="link-section">${escapeHtml(entry.title)}</h2>`
          : entry.kind === "text"
            ? entry.markdown
              ? `<div class="link-text md">${renderTextBlockMarkdown(entry.text)}</div>`
              : `<p class="link-text">${escapeHtml(entry.text)}</p>`
            : `<a class="contact-link" href="${escapeHtml(entry.link.href)}"${linkRelAttr(entry.link)}>${linkInner(entry.link)}</a>`,
      ),
    ].join("\n    ")}
  </nav>`
      : ""
  }
</main>
</body>
</html>`;
}

export function recoveryKitHtml(path: string, pw: string, url: string): string {
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

// Links the owner marked "include on business cards", as {emoji, text} lines.
export function businessCardLines(
  tree: LinkTree,
): { icon: string; text: string }[] {
  return tree.links
    .filter((link) => link.card && !isBlock(link))
    .map((link) => ({
      icon: linkIconEmoji(link.icon) ?? kindDefaultIcons[link.kind] ?? "",
      text: link.value.trim() || link.label.trim(),
    }))
    .filter((line) => line.text);
}

export function printablesHtml(
  tree: LinkTree,
  url: string,
  display: string,
): string {
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
  const contacts = businessCardLines(tree);
  const contactsHtml = contacts.length
    ? `<div class="card-contacts">${contacts
        .map(
          (c) =>
            `<p class="card-contact">${c.icon ? escapeHtml(c.icon) + " " : ""}${escapeHtml(c.text)}</p>`,
        )
        .join("")}</div>`
    : "";
  const card = `<div class="card">
  <div class="card-text">
    <p class="card-name">${escapeHtml(name)}</p>
    ${bio ? `<p class="card-bio">${escapeHtml(bio)}</p>` : ""}
    ${contactsHtml}
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
.card { width: 85mm; height: 55mm; display: flex; align-items: center; gap: 4mm; padding: 6mm; break-inside: avoid; overflow: hidden; }
.mark { position: absolute; }
.mark-v { width: 0; height: 6mm; border-left: 0.2mm solid #9a9a94; }
.mark-h { width: 6mm; height: 0; border-top: 0.2mm solid #9a9a94; }
.card svg { flex: none; }
.card-text { flex: 1; min-width: 0; }
.card-name { margin: 0; font-size: 12pt; font-weight: 800; line-height: 1.25; }
.card-bio { margin: 1mm 0 0; color: #595959; font-size: 8pt; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.card-contacts { margin: 1.5mm 0 0; display: grid; gap: 0.3mm; }
.card-contact { margin: 0; font-size: 8.5pt; color: #333333; line-height: 1.3; overflow-wrap: anywhere; }
.card-url { margin: 1.5mm 0 0; color: ${accent}; font-size: 9pt; font-weight: 700; overflow-wrap: anywhere; }
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
