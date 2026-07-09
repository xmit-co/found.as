export enum Type {
  HTML_PAGE,
  MARKDOWN_PAGE,
  REDIR,
  BYTES,
  LINK_TREE,
}

export type BuilderMode = "contact" | "advanced";

export type LinkKind =
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
  | "googlereview"
  | "custom"
  | "section"
  | "text"
  | "video";

export interface LinkItem {
  id: string;
  kind: LinkKind;
  label: string;
  value: string;
  href: string;
  enabled: boolean;
  featured?: boolean;
  icon?: string;
  relMe?: boolean;
  // Print this link's value on the business cards (independent of showing it
  // on the page). Handy for an email or phone number.
  card?: boolean;
  // A subtitle shown under the button label.
  desc?: string;
  // A short tag shown on the button (e.g. "New").
  badge?: string;
  // Text blocks only: render the text as GitHub-flavored Markdown instead of
  // plain text. Opt-in, so a stray *, _ or # stays literal by default.
  markdown?: boolean;
}

export interface SocialPreview {
  title?: string;
  description?: string;
  // Custom preview image as a data URL; published as the page's `og` sub.
  customImage?: string;
  autoImage?: boolean;
  // Render the automatic image dark (Dark-themed pages always do).
  imageDark?: boolean;
}

export type FontChoice = "system" | "sans" | "serif" | "mono" | "rounded";
export type ButtonStyle = "soft" | "outline" | "filled";
export type Corners = "rounded" | "sharp" | "pill";
export type AvatarShape = "circle" | "rounded";
export type Background = "none" | "gradient" | "dots" | "grid" | "image";
// How the cover image sits in its band: fill (crop to fill, region chosen by
// coverPos) or fit the whole image with no cropping.
export type CoverFit = "cover" | "contain";

export interface LinkTree {
  displayName: string;
  bio: string;
  // The email link (by id) shared through the IndieAuth profile's `email`
  // scope. Only meaningful with more than one email link; otherwise the sole
  // email (if any) is used.
  profileEmailId?: string;
  avatarUrl?: string;
  // Focal point + zoom of the photo within its frame.
  avatarPos?: string;
  avatarZoom?: number;
  coverUrl?: string;
  coverFit?: CoverFit;
  // Focal point + zoom of the cover within its band.
  coverPos?: string;
  coverZoom?: number;
  // Height of the cover band in px, when filling.
  coverHeight?: number;
  // When set (and a cover is present), the cover stands in for the name, which
  // is kept only for screen readers and metadata.
  coverTitle?: boolean;
  theme: "system" | "light" | "dark";
  accent?: string;
  font?: FontChoice;
  buttons?: ButtonStyle;
  // Button surface: background opacity (%) and backdrop blur (px), for
  // glassy buttons over image backgrounds.
  btnAlpha?: number;
  btnBlur?: number;
  corners?: Corners;
  avatarShape?: AvatarShape;
  background?: Background;
  // Custom background: the uploaded image is served as-is (as a sub). Light
  // themes show it under a white overlay at bgLighten%; dark ones swap in the
  // custom upload if any and lay black at bgShade% — CSS overlays everywhere.
  bgUrl?: string;
  bgDarkUrl?: string;
  bgShade?: number;
  bgLighten?: number;
  // A short "now" status line under the name.
  status?: string;
  // An emoji used as the page's favicon (browser tab icon).
  favicon?: string;
  social?: SocialPreview;
  showVcard?: boolean;
  links: LinkItem[];
}

export interface Private {
  type: Type;
  md: string;
  html: string;
  redir: string;
  linkTree?: LinkTree;
}

export interface Public {
  redir?: string;
  html?: string;
  mime?: string;
  bytes?: Uint8Array;
  subs?: Record<string, { mime: string; bytes: Uint8Array }>;
  // Structured profile surfaced by the IndieAuth profile/email scopes. The
  // profile URL isn't stored here — the backend fills it with the identity that
  // signed in.
  profile?: { name?: string; photo?: string; email?: string };
}

export interface NormalizedLink {
  item: LinkItem;
  label: string;
  href: string;
  warning?: string;
  error?: string;
}

export interface CompressedAvatar {
  dataUrl: string;
  mime: "image/avif" | "image/jpeg";
  size: number;
}

export class FourOFour extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class FourXX extends Error {
  constructor(message: string) {
    super(message);
  }
}

// The add menu, grouped so generic contact details sit apart from platforms.
export const addGroups: { label: string; kinds: LinkKind[] }[] = [
  {
    label: "Content",
    kinds: ["section", "text", "video"],
  },
  {
    label: "Contact",
    kinds: ["phone", "email", "website", "address", "custom"],
  },
  {
    label: "Platforms",
    kinds: [
      "whatsapp",
      "instagram",
      "tiktok",
      "youtube",
      "linkedin",
      "x",
      "facebook",
      "telegram",
      "signal",
      "matrix",
      "github",
      "mastodon",
      "bluesky",
      "threads",
      "reddit",
      "twitch",
      "snapchat",
      "pinterest",
      "discord",
      "spotify",
      "substack",
      "medium",
      "patreon",
      "calendly",
      "googlereview",
    ],
  },
  {
    label: "Payments",
    kinds: ["paypal", "venmo", "cashapp"],
  },
];

export const kindLabels: Record<LinkKind, string> = {
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
  googlereview: "Google review",
  custom: "Custom link",
  section: "Section header",
  text: "Text",
  video: "Video",
};

export const kindExamples: Record<LinkKind, string> = {
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
  googlereview: "g.page/r/…/review",
  custom: "https://example.com",
  section: "Work",
  text: "A line or two of text",
  video: "youtube.com, vimeo.com, or a PeerTube link",
};

export const kindDefaultValues: Record<LinkKind, string> = {
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
  googlereview: "",
  custom: "https://",
  section: "",
  text: "",
  video: "",
};

export const kindDefaultIcons: Partial<Record<LinkKind, string>> = {
  phone: "📞",
  email: "✉️",
  website: "🌐",
  address: "📍",
  googlereview: "⭐",
  calendly: "📅",
  custom: "🔗",
};

// Kinds whose link points at something that is "also you" — a profile,
// address, or number — published with rel="me" identity metadata, which also
// lets Mastodon and other IndieWeb sites verify page ownership.
export const identityKinds = new Set<LinkKind>([
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

export const kindIconSites: Partial<Record<LinkKind, string>> = {
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

// Contact details worth printing on a business card by default.
export const defaultCardKinds = new Set<LinkKind>([
  "email",
  "phone",
  "whatsapp",
]);

export const handleKinds: LinkKind[] = [
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
