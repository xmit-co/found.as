import { LinkTree } from "./types";

// The accent is picked on an OKLCH hue/chroma wheel (hue around, chroma out
// from gray at the center) and every other page color is derived from it. The
// accent doubles as text and borders on the page background, and the System
// theme flips that background with the OS — so lightness is fixed per theme
// variant at values where *any* point on the wheel meets WCAG AA, both as text
// on its page background (#fbfbf8 / #101112) and under its button label (white
// on the light variant, near-black on the dark one). Worst case over all hues
// at max chroma: 4.52:1 light, 5.85:1 dark.
export interface AccentPair {
  light: string;
  dark: string;
}

export const accentLightText = "#ffffff";
export const accentDarkText = "#10130f";

export const accentLightL = 0.54;
export const accentDarkL = 0.68;
export const accentMaxChroma = 0.2;

// Earlier pages stored one of eight curated palette names; map those to the
// nearest wheel position (same hue and chroma, at the fixed lightness).
export const legacyAccents: Record<string, string> = {
  ocean: "266 0.185",
  violet: "302 0.190",
  magenta: "356 0.200",
  crimson: "22 0.200",
  rust: "47 0.140",
  forest: "155 0.130",
  gold: "81 0.110",
  graphite: "248 0.025",
};

// Stored accent: "" for the theme default, or "<hue> <chroma>" on the wheel.
export function parseAccent(
  value: string | undefined,
): { hue: number; chroma: number } | null {
  if (!value) return null;
  const stored = legacyAccents[value] ?? value;
  const m = stored.match(/^(\d{1,3}(?:\.\d+)?) (0(?:\.\d+)?)$/);
  if (!m) return null;
  const hue = Number(m[1]);
  const chroma = Number(m[2]);
  return hue < 360 && chroma <= accentMaxChroma ? { hue, chroma } : null;
}

export function linearToSrgb(c: number): number {
  return c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055;
}

export function oklchToLinearSrgb(l: number, c: number, h: number): number[] {
  const a = c * Math.cos((h * Math.PI) / 180);
  const b = c * Math.sin((h * Math.PI) / 180);
  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
    -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
    -0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_,
  ];
}

// OKLCH → sRGB hex, reducing chroma into gamut where needed (as CSS does).
// Hex keeps every consumer working: published CSS, canvas og:images, print.
export function oklchToHex(l: number, c: number, h: number): string {
  let rgb = oklchToLinearSrgb(l, c, h);
  while (rgb.some((v) => v < 0 || v > 1) && c > 0) {
    c = Math.max(0, c - 0.002);
    rgb = oklchToLinearSrgb(l, c, h);
  }
  return `#${rgb
    .map((v) =>
      Math.round(linearToSrgb(Math.min(1, Math.max(0, v))) * 255)
        .toString(16)
        .padStart(2, "0"),
    )
    .join("")}`;
}

export function accentPair(value: string | undefined): AccentPair | null {
  const parsed = parseAccent(value);
  if (!parsed) return null;
  return {
    light: oklchToHex(accentLightL, parsed.chroma, parsed.hue),
    dark: oklchToHex(accentDarkL, parsed.chroma, parsed.hue),
  };
}

export const themeAccentDefaults: Record<LinkTree["theme"], string> = {
  system: "#007f73",
  light: "#007f73",
  dark: "#4fc3b3",
};

// Approximates CSS color-mix(in srgb, a pct%, b) for 6-digit hex colors.
export function mixHex(a: string, b: string, pct: number): string {
  const pa = parseInt(a.slice(1), 16);
  const pb = parseInt(b.slice(1), 16);
  const t = pct / 100;
  const ch = (shift: number) =>
    Math.round(((pa >> shift) & 255) * t + ((pb >> shift) & 255) * (1 - t)) <<
    shift;
  return `#${(ch(16) | ch(8) | ch(0)).toString(16).padStart(6, "0")}`;
}

// Accents legible on white for print, per theme (the dark theme's on-screen
// accent is too pale for paper, so it borrows the system pair's light variant).
export const printAccents: Record<LinkTree["theme"], string> = {
  system: "#007f73",
  light: "#007f73",
  dark: "#007f73",
};
