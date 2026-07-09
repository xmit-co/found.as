import { normalizeUrl } from "./linktree";
import { FontChoice, LinkTree, LoadedFont } from "./types";
import { splitGraphemes } from "./util";

export function avatarImageSrc(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (/^data:image\/(avif|jpeg|jpg|png|webp);base64,/i.test(trimmed)) {
    return trimmed;
  }
  const normalized = normalizeUrl(trimmed);
  return URL.canParse(normalized) ? normalized : null;
}

// Curated system-font stacks — request-free by default. An optional loaded
// font (tree.loadedFont) is prepended by name; the chosen stack is its fallback.
export const fontStacks: Record<FontChoice, string> = {
  system: "system-ui, sans-serif",
  sans: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  serif: 'ui-serif, Georgia, Cambria, "Times New Roman", serif',
  mono: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
  rounded:
    'ui-rounded, "SF Pro Rounded", "Hiragino Maru Gothic ProN", "Segoe UI", system-ui, sans-serif',
};

export function fontStack(tree: LinkTree): string {
  const fallback = fontStacks[tree.font ?? "system"];
  const loaded = tree.loadedFont?.name?.trim().replace(/["';]/g, "");
  return loaded ? `"${loaded}", ${fallback}` : fallback;
}

// @font-face rules for a loaded font, one per face, served from cc.me/fonts.
// Variable faces declare the whole weight axis (one file covers every weight);
// static faces declare their own weight. font-display: swap keeps text visible.
export function fontFaceCss(font: LoadedFont): string {
  const family = font.name.replace(/["\\]/g, "");
  return font.faces
    .map((face) => {
      const url = `https://cc.me/fonts/${encodeURIComponent(font.slug)}/${encodeURIComponent(face.file)}`;
      const weight = font.variable ? "100 900" : String(face.weight);
      const style = face.italic ? "italic" : "normal";
      return `@font-face{font-family:"${family}";font-style:${style};font-weight:${weight};font-display:swap;src:url("${url}") format("truetype");}`;
    })
    .join("");
}

export function cornerRadius(tree: LinkTree): string {
  return tree.corners === "sharp"
    ? "3px"
    : tree.corners === "pill"
      ? "999px"
      : "8px";
}

export function avatarRadius(tree: LinkTree): string {
  return tree.avatarShape === "rounded" ? "22%" : "50%";
}

// Cover band height in px, clamped to a sane range.
export function clampCoverHeight(h: number | undefined): number {
  return Math.min(400, Math.max(72, Math.round(Number(h) || 132)));
}

// Zoom factor for a cover/photo, clamped to 1–4×.
export function clampZoom(z: number | undefined): number {
  const n = Number(z);
  return Math.min(4, Math.max(1, Number.isFinite(n) && n > 0 ? n : 1));
}

// How much to darken a light background to make the dark one, 0–90%.
export function clampShade(s: number | undefined): number {
  const n = Number(s);
  return Math.min(90, Math.max(0, Number.isFinite(n) ? Math.round(n) : 55));
}

// Button background opacity, 10–100%.
export function clampBtnAlpha(v: number | undefined): number {
  const n = Number(v);
  return Math.min(100, Math.max(10, Number.isFinite(n) ? Math.round(n) : 100));
}

// Backdrop blur behind buttons, 0–24px.
export function clampBtnBlur(v: number | undefined): number {
  const n = Number(v);
  return Math.min(24, Math.max(0, Number.isFinite(n) ? Math.round(n) : 0));
}

// How much to lighten the background's light version, 0–90%. Defaults to 0 so
// existing pages keep showing the image as uploaded.
export function clampLighten(s: number | undefined): number {
  const n = Number(s);
  return Math.min(90, Math.max(0, Number.isFinite(n) ? Math.round(n) : 0));
}

// Parses a stored "x% y%" focal point, clamped to 0–100, defaulting to center.
// Sanitized because it is interpolated into CSS.
export function sanitizeObjectPosition(pos: string | undefined): string {
  const m = (pos ?? "").match(/^(\d{1,3}(?:\.\d+)?)%\s+(\d{1,3}(?:\.\d+)?)%$/);
  if (!m) return "50% 50%";
  const x = Math.min(100, Math.max(0, parseFloat(m[1])));
  const y = Math.min(100, Math.max(0, parseFloat(m[2])));
  return `${x}% ${y}%`;
}

// CSS `background` shorthand for the page body, tinted with the accent so
// patterns track the theme. Pure CSS — no external assets or scripts. Accepts
// the accent/bg variable names so it works both on the published page (--accent
// / --bg) and in the editor preview (--pv-accent / --pv-bg).
export function pageBackground(
  tree: LinkTree,
  accentVar = "--accent",
  bgVar = "--bg",
): string {
  const a = `var(${accentVar})`;
  const b = `var(${bgVar})`;
  switch (tree.background) {
    case "gradient":
      return `radial-gradient(120% 90% at 50% 0%, color-mix(in srgb, ${a} 18%, ${b}), ${b} 72%)`;
    case "dots":
      return `radial-gradient(color-mix(in srgb, ${a} 26%, transparent) 1.4px, transparent 1.5px) 0 0 / 22px 22px, ${b}`;
    case "grid":
      return `linear-gradient(color-mix(in srgb, ${a} 16%, transparent) 1px, transparent 1px) 0 0 / 26px 26px, linear-gradient(90deg, color-mix(in srgb, ${a} 16%, transparent) 1px, transparent 1px) 0 0 / 26px 26px, ${b}`;
    default:
      return b;
  }
}

export const linkIconPattern =
  /^data:image\/[a-z0-9.+-]+;base64,[a-z0-9+/=]+$/i;
export const linkIconMaxRawBytes = 16 * 1024;

export function linkIconSrc(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed && linkIconPattern.test(trimmed) ? trimmed : null;
}

export function linkIconEmoji(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed || trimmed.length > 16 || trimmed.startsWith("data:")) {
    return null;
  }
  return splitGraphemes(trimmed).length === 1 ? trimmed : null;
}
