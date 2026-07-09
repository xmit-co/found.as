import { accentPair } from "./color";
import {
  avatarImageSrc,
  clampBtnAlpha,
  clampBtnBlur,
  clampCoverHeight,
  clampLighten,
  clampShade,
  clampZoom,
} from "./theme";
import {
  LinkItem,
  LinkKind,
  LinkTree,
  NormalizedLink,
  Private,
  Type,
  defaultCardKinds,
  kindDefaultIcons,
  kindDefaultValues,
  kindLabels,
} from "./types";
import { marked } from "marked";

export function makeId(): string {
  if (window.crypto.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function isSection(item: LinkItem): boolean {
  return item.kind === "section";
}

export function isText(item: LinkItem): boolean {
  return item.kind === "text";
}

// A YouTube embed block: its `value` holds the video URL.
export function isVideo(item: LinkItem): boolean {
  return item.kind === "video";
}

// Section headings, text blocks and video embeds are organizational/media, not
// links: they carry no button href and can't be featured, iconed, or carded.
export function isBlock(item: LinkItem): boolean {
  return isSection(item) || isText(item) || isVideo(item);
}

export function defaultLinkItem(kind: LinkKind): LinkItem {
  return {
    id: makeId(),
    kind,
    label:
      kind === "section" || kind === "text" || kind === "video"
        ? ""
        : kindLabels[kind],
    value: kindDefaultValues[kind],
    href: "",
    enabled: true,
    icon: kindDefaultIcons[kind],
    card: defaultCardKinds.has(kind) || undefined,
  };
}

export function createDefaultLinkTree(): LinkTree {
  return {
    displayName: "",
    bio: "",
    theme: "system",
    links: [],
  };
}

export function createDefaultPrivate(): Private {
  return {
    type: Type.LINK_TREE,
    md: "",
    html: "",
    redir: "",
    linkTree: createDefaultLinkTree(),
  };
}

export function ensureLinkTree(tree: LinkTree | undefined): LinkTree {
  const current = tree ?? createDefaultLinkTree();
  return {
    displayName: current.displayName ?? "",
    bio: current.bio ?? "",
    profileEmailId: current.profileEmailId,
    avatarUrl: current.avatarUrl ?? "",
    avatarPos: current.avatarPos ?? "50% 50%",
    avatarZoom: clampZoom(current.avatarZoom),
    coverUrl: current.coverUrl ?? "",
    coverFit: current.coverFit === "contain" ? "contain" : "cover",
    coverZoom: clampZoom(current.coverZoom),
    coverHeight: clampCoverHeight(current.coverHeight),
    coverPos:
      current.coverPos ??
      // Migrate the retired top/bottom fit values to a focal point.
      ((current.coverFit as string) === "top"
        ? "50% 0%"
        : (current.coverFit as string) === "bottom"
          ? "50% 100%"
          : "50% 50%"),
    coverTitle: current.coverTitle ?? false,
    theme:
      current.theme === "light" || current.theme === "dark"
        ? current.theme
        : "system",
    accent: accentPair(current.accent) ? current.accent : "",
    font: current.font ?? "system",
    buttons: current.buttons ?? "soft",
    btnAlpha: clampBtnAlpha(current.btnAlpha),
    btnBlur: clampBtnBlur(current.btnBlur),
    corners: current.corners ?? "rounded",
    avatarShape: current.avatarShape ?? "circle",
    background: current.background ?? "none",
    bgUrl: current.bgUrl ?? "",
    bgDarkUrl: current.bgDarkUrl ?? "",
    bgShade: clampShade(current.bgShade),
    bgLighten: clampLighten(current.bgLighten),
    status: current.status ?? "",
    favicon: current.favicon ?? "",
    social: {
      title: current.social?.title ?? "",
      description: current.social?.description ?? "",
      customImage: current.social?.customImage ?? "",
      autoImage: current.social?.autoImage ?? true,
      imageDark: current.social?.imageDark ?? false,
    },
    showVcard: current.showVcard ?? true,
    links: current.links ?? [],
  };
}

export function normalizePrivate(priv: Private): Private {
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

export function normalizeUrl(url: string): string {
  // Pasted URLs often pick up spaces or line breaks (PDFs, emails); URLs
  // never legitimately contain whitespace, so drop it all.
  const stripped = url.replace(/\s+/g, "");
  if (!stripped) return stripped;
  if (!stripped.includes("://")) {
    return `https://${stripped}`;
  }
  return stripped;
}

export function normalizeSocialUsername(value: string): string {
  return value.trim().replace(/^@+/, "").replace(/^\/+/, "").split("?")[0];
}

export function valueFromKnownHost(
  value: string,
  hosts: string[],
): string | null {
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

export function normalizePhone(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
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

export function normalizeWhatsApp(
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

export function normalizeEmail(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const address = value.trim().replace(/^mailto:/i, "");
  if (!address) {
    return { href: "", error: "Enter an email address." };
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
    return { href: "", error: "Enter a valid email address." };
  }
  return { href: `mailto:${encodeURI(address)}` };
}

export function normalizeInstagram(
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

export function normalizeUsernameUrl(
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

export function normalizeBluesky(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "https://bsky.app/profile/") {
    return { href: "", error: "Enter a Bluesky handle or link." };
  }
  if (trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    return URL.canParse(normalized)
      ? { href: normalized }
      : { href: "", error: "Enter a valid Bluesky link." };
  }
  const handle = trimmed.replace(/^@+/, "");
  if (!handle) {
    return { href: "", error: "Enter a Bluesky handle." };
  }
  return { href: `https://bsky.app/profile/${encodeURIComponent(handle)}` };
}

export function normalizeMastodon(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter a Mastodon address or link." };
  }
  if (trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    return URL.canParse(normalized)
      ? { href: normalized }
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

export function normalizeMatrix(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter a Matrix ID or link." };
  }
  if (trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    return URL.canParse(normalized)
      ? { href: normalized }
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

export function normalizeSubstack(
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

export function normalizeCashApp(
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

export function normalizeMap(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Enter an address or map link." };
  }
  if (trimmed.includes("://")) {
    const normalized = normalizeUrl(trimmed);
    if (!URL.canParse(normalized)) {
      return { href: "", error: "Enter a valid map link." };
    }
    return { href: normalized };
  }
  return {
    href: `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(trimmed)}`,
  };
}

export function normalizeGoogleReview(
  value: string,
): Omit<NormalizedLink, "item" | "label"> {
  const trimmed = value.trim();
  if (!trimmed) {
    return { href: "", error: "Paste your Google review link." };
  }
  const normalized = normalizeUrl(trimmed);
  if (!normalized || !URL.canParse(normalized)) {
    return { href: "", error: "Paste a valid Google review link." };
  }
  return { href: normalized };
}

export function normalizeGenericLink(
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

export function normalizeByKind(
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
    case "googlereview":
      return normalizeGoogleReview(value);
    default:
      return normalizeGenericLink(value, label, kindDefaultValues[kind]);
  }
}

export function isAllowedHref(href: string): boolean {
  if (!URL.canParse(href)) return false;
  const protocol = new URL(href).protocol;
  return (
    protocol === "https:" ||
    protocol === "http:" ||
    protocol === "mailto:" ||
    protocol === "tel:"
  );
}

export function normalizeLink(item: LinkItem): NormalizedLink {
  const label = item.label.trim() || kindLabels[item.kind];
  if (isVideo(item)) {
    const value = item.value.trim();
    if (!item.enabled || !value) {
      return { item, label, href: "" };
    }
    return youTubeId(value)
      ? { item, label, href: "" }
      : {
          item,
          label,
          href: "",
          error: "Enter a YouTube link (youtube.com or youtu.be).",
        };
  }
  if (isBlock(item)) {
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

export function normalizedLinks(tree: LinkTree): NormalizedLink[] {
  return tree.links.map(normalizeLink);
}

export function isDefaultLinkValue(link: LinkItem): boolean {
  const value = link.value.trim().replace(/\/$/, "");
  const defaultValue = kindDefaultValues[link.kind].trim().replace(/\/$/, "");
  return Boolean(defaultValue) && value === defaultValue;
}

export function activeValidLinks(tree: LinkTree): NormalizedLink[] {
  return normalizedLinks(tree).filter((link) => link.href && !link.error);
}

export function canFeature(link: LinkItem): boolean {
  return !isBlock(link);
}

export type RenderEntry =
  | { kind: "section"; title: string; id: string }
  | { kind: "text"; text: string; id: string; markdown?: boolean }
  | { kind: "video"; id: string; itemId: string }
  | { kind: "link"; link: NormalizedLink };

// Renders an opt-in Markdown text block to HTML. Same GitHub-flavored settings
// as the standalone Markdown page type, so both behave alike; the content is the
// owner's own, published on their own page — the same trust model as everywhere.
// A YouTube URL → its video id, or null when it isn't one.
export function youTubeId(rawUrl: string): string | null {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  const host = u.hostname.replace(/^(www\.|m\.)/, "").toLowerCase();
  let id = "";
  if (host === "youtu.be") {
    id = u.pathname.slice(1);
  } else if (host === "youtube.com" || host === "youtube-nocookie.com") {
    if (u.pathname === "/watch") id = u.searchParams.get("v") ?? "";
    else {
      const m = u.pathname.match(/^\/(?:embed|shorts|v|live)\/([^/?#]+)/);
      if (m) id = m[1];
    }
  }
  return /^[A-Za-z0-9_-]{6,20}$/.test(id) ? id : null;
}

// A privacy-preserving (nocookie) responsive embed — no tracking until the
// viewer hits play, matching found.as's no-tracking stance.
export function youTubeEmbedHtml(id: string): string {
  return `<div class="yt-embed"><iframe src="https://www.youtube-nocookie.com/embed/${id}" title="YouTube video" loading="lazy" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe></div>`;
}

export function renderTextBlockMarkdown(text: string): string {
  return marked.parse(text, { gfm: true, breaks: true }) as string;
}

// Tags kept when rendering a markdown block inline in the editor, which runs on
// the be.found.as origin (where page keys live) — unlike the published page's
// own isolated origin. Everything else is unwrapped.
const editorAllowedTags = new Set([
  "p",
  "br",
  "strong",
  "em",
  "b",
  "i",
  "del",
  "code",
  "pre",
  "blockquote",
  "ul",
  "ol",
  "li",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "a",
  "hr",
  "img",
  "div",
  "span",
  "iframe",
]);

// sanitizeEditorHtml allowlists the output of renderTextBlockMarkdown for safe
// inline injection in the editor: it keeps formatting and the YouTube embed but
// drops scripts, event handlers, javascript:/foreign iframes and unknown tags.
export function sanitizeEditorHtml(html: string): string {
  const doc = new DOMParser().parseFromString(
    `<body>${html}</body>`,
    "text/html",
  );
  const walk = (parent: Element) => {
    for (const el of Array.from(parent.children)) {
      const tag = el.tagName.toLowerCase();
      if (!editorAllowedTags.has(tag)) {
        el.replaceWith(...Array.from(el.childNodes));
        continue;
      }
      if (
        tag === "iframe" &&
        !(el.getAttribute("src") ?? "").startsWith(
          "https://www.youtube-nocookie.com/embed/",
        )
      ) {
        el.remove();
        continue;
      }
      for (const attr of Array.from(el.attributes)) {
        const name = attr.name.toLowerCase();
        const value = attr.value;
        const keep =
          (tag === "a" &&
            name === "href" &&
            /^(https?:|mailto:)/i.test(value)) ||
          (tag === "img" &&
            name === "src" &&
            /^(https?:|data:image\/)/i.test(value)) ||
          (tag === "img" && (name === "alt" || name === "title")) ||
          (tag === "iframe" &&
            [
              "src",
              "title",
              "loading",
              "allow",
              "allowfullscreen",
              "referrerpolicy",
            ].includes(name)) ||
          (tag === "div" && name === "class" && value === "yt-embed");
        if (!keep) el.removeAttribute(attr.name);
      }
      walk(el);
    }
  };
  walk(doc.body);
  return doc.body.innerHTML;
}

export function linkTreeRenderEntries(tree: LinkTree): RenderEntry[] {
  const entries: RenderEntry[] = [];
  for (const normalized of normalizedLinks(tree)) {
    if (isSection(normalized.item)) {
      const title = normalized.item.label.trim();
      if (normalized.item.enabled && title) {
        entries.push({ kind: "section", title, id: normalized.item.id });
      }
      continue;
    }
    if (isText(normalized.item)) {
      const text = normalized.item.label.trim();
      if (normalized.item.enabled && text) {
        entries.push({
          kind: "text",
          text,
          id: normalized.item.id,
          markdown: normalized.item.markdown || undefined,
        });
      }
      continue;
    }
    if (isVideo(normalized.item)) {
      const id = normalized.item.enabled
        ? youTubeId(normalized.item.value.trim())
        : null;
      if (id) {
        entries.push({ kind: "video", id, itemId: normalized.item.id });
      }
      continue;
    }
    if (normalized.href && !normalized.error) {
      entries.push({ kind: "link", link: normalized });
    }
  }
  return entries;
}

export function featuredLink(tree: LinkTree): NormalizedLink | undefined {
  return activeValidLinks(tree).find(
    (link) => link.item.featured && canFeature(link.item),
  );
}

export function linkTreeListedEntries(tree: LinkTree): RenderEntry[] {
  const featured = featuredLink(tree);
  const listed = featured
    ? linkTreeRenderEntries(tree).filter(
        (entry) => entry.kind !== "link" || entry.link.item !== featured.item,
      )
    : linkTreeRenderEntries(tree);
  return listed;
}

export function linkTreeHasPublishableContent(tree: LinkTree): boolean {
  return Boolean(
    tree.displayName.trim() ||
    tree.bio.trim() ||
    avatarImageSrc(tree.avatarUrl) ||
    activeValidLinks(tree).length,
  );
}

export function linkTreeErrors(tree: LinkTree): string[] {
  const errors = normalizedLinks(tree)
    .filter(
      (link) =>
        link.error &&
        link.item.enabled &&
        link.item.value.trim() &&
        !isDefaultLinkValue(link.item),
    )
    .map((link) => `${link.label}: ${link.error}`);
  return errors;
}
