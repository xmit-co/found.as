import { accentDarkText, accentLightText, accentPair, mixHex } from "./color";
import { loadImageFromSrc } from "./image";
import {
  avatarImageSrc,
  clampCoverHeight,
  clampLighten,
  clampShade,
  clampZoom,
  cornerRadius,
  sanitizeObjectPosition,
} from "./theme";
import { LinkTree } from "./types";

export interface OgColors {
  bg: string;
  text: string;
  muted: string;
  accent: string;
  accentText: string;
}

// og:image renders one fixed look. The owner picks light or dark for the
// automatic image; a Dark theme is always dark.
export function ogImageDark(tree: LinkTree): boolean {
  return tree.theme === "dark" || Boolean(tree.social?.imageDark);
}

export function ogColors(tree: LinkTree): OgColors {
  const pair = accentPair(tree.accent);
  if (ogImageDark(tree)) {
    return {
      bg: "#101112",
      text: "#f5f5f0",
      muted: "#c1c1ba",
      accent: pair?.dark ?? "#4fc3b3",
      accentText: pair ? accentDarkText : "#07100f",
    };
  }
  return {
    bg: "#fbfbf8",
    text: "#181818",
    muted: "#595959",
    accent: pair?.light ?? "#007f73",
    accentText: pair ? accentLightText : "#ffffff",
  };
}

// Replicates the page background on the og:image canvas: the pageBackground
// patterns, or the custom image with the same light/dark treatment the
// published page serves. System renders as light, matching ogColors.
export async function drawOgBackground(
  ctx: CanvasRenderingContext2D,
  tree: LinkTree,
  colors: OgColors,
): Promise<void> {
  const w = 1200;
  const h = 630;
  ctx.fillStyle = colors.bg;
  ctx.fillRect(0, 0, w, h);
  const dark = ogImageDark(tree);
  if (tree.background === "image") {
    // Only data: URLs are drawn — a remote image would taint the canvas.
    const src =
      dark && tree.bgDarkUrl?.trim().startsWith("data:")
        ? tree.bgDarkUrl
        : tree.bgUrl?.trim().startsWith("data:")
          ? tree.bgUrl
          : null;
    if (!src) return;
    try {
      const img = await loadImageFromSrc(src);
      const scale = Math.max(w / img.naturalWidth, h / img.naturalHeight);
      const iw = img.naturalWidth * scale;
      const ih = img.naturalHeight * scale;
      ctx.drawImage(img, (w - iw) / 2, (h - ih) / 2, iw, ih);
      // The same overlays the published page lays over each variant.
      const overlay = dark
        ? clampShade(tree.bgShade) / 100
        : clampLighten(tree.bgLighten) / 100;
      if (overlay > 0) {
        ctx.fillStyle = `rgba(${dark ? "0, 0, 0" : "255, 255, 255"}, ${overlay})`;
        ctx.fillRect(0, 0, w, h);
      }
    } catch {
      // Keep the flat background.
    }
    return;
  }
  // Pattern cells are drawn at 2× their CSS pixel size: the 1200px-wide
  // og:image is typically displayed around half size.
  if (tree.background === "gradient") {
    // radial-gradient(120% 90% at 50% 0%, mix(accent 18%, bg), bg 72%)
    ctx.save();
    ctx.translate(w / 2, 0);
    ctx.scale(1, (0.9 * h) / (1.2 * w));
    const g = ctx.createRadialGradient(0, 0, 0, 0, 0, 1.2 * w);
    g.addColorStop(0, mixHex(colors.accent, colors.bg, 18));
    g.addColorStop(0.72, colors.bg);
    ctx.fillStyle = g;
    ctx.fillRect(-w / 2, 0, w, (h * (1.2 * w)) / (0.9 * h));
    ctx.restore();
  } else if (tree.background === "dots") {
    ctx.fillStyle = mixHex(colors.accent, colors.bg, 26);
    for (let y = 0; y <= h + 44; y += 44) {
      for (let x = 0; x <= w + 44; x += 44) {
        ctx.beginPath();
        ctx.arc(x, y, 2.8, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  } else if (tree.background === "grid") {
    ctx.strokeStyle = mixHex(colors.accent, colors.bg, 16);
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let x = 0; x <= w; x += 52) {
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
    }
    for (let y = 0; y <= h; y += 52) {
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
    }
    ctx.stroke();
  }
}

export function wrapCanvasText(
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

export async function renderOgImage(
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

  await drawOgBackground(ctx, tree, colors);

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
  const drawName = () => {
    let nameSize = 68;
    ctx.font = font(800, nameSize);
    while (ctx.measureText(name).width > 1040 && nameSize > 34) {
      nameSize -= 4;
      ctx.font = font(800, nameSize);
    }
    ctx.fillStyle = colors.text;
    ctx.fillText(name, 600, nameY);
  };

  // When the cover replaces the name, draw it as the title band, mirroring
  // the page's fit/position/zoom. Only data: covers — remote would taint.
  const coverSrc =
    tree.coverTitle && tree.coverUrl?.trim().startsWith("data:")
      ? avatarImageSrc(tree.coverUrl)
      : null;
  let bioY = nameY + 66;
  let coverDrawn = false;
  if (coverSrc) {
    try {
      const img = await loadImageFromSrc(coverSrc);
      const bandTop = avatarSrc ? 288 : 100;
      // The page band is the content width (440) with a crop window of
      // 440:coverHeight ("cover") or the image's own aspect ("contain");
      // the og draws it at 2×, scaled down uniformly when the layout needs
      // it so the crop matches the page's exactly.
      const fullW = 880;
      const desiredH =
        tree.coverFit === "contain"
          ? (fullW * img.naturalHeight) / img.naturalWidth
          : clampCoverHeight(tree.coverHeight) * 2;
      const capH = Math.max(64, (bio ? 372 : 460) - bandTop);
      const bh = Math.min(desiredH, capH);
      const bw = fullW * (bh / desiredH);
      const bx = 600 - bw / 2;
      const radius = Math.min(
        parseInt(cornerRadius(tree), 10) * 2 * (bw / fullW),
        bw / 2,
        bh / 2,
      );
      ctx.save();
      ctx.beginPath();
      ctx.roundRect(bx, bandTop, bw, bh, radius);
      ctx.clip();
      if (tree.coverFit === "contain") {
        ctx.drawImage(img, bx, bandTop, bw, bh);
      } else {
        const [px, py] = sanitizeObjectPosition(tree.coverPos)
          .split(" ")
          .map((v) => parseFloat(v) / 100);
        const s =
          Math.max(bw / img.naturalWidth, bh / img.naturalHeight) *
          clampZoom(tree.coverZoom);
        const iw = img.naturalWidth * s;
        const ih = img.naturalHeight * s;
        ctx.drawImage(
          img,
          bx + (bw - iw) * px,
          bandTop + (bh - ih) * py,
          iw,
          ih,
        );
      }
      ctx.restore();
      bioY = bandTop + bh + 60;
      coverDrawn = true;
    } catch {
      // Fall back to the name text.
    }
  }
  if (!coverDrawn) {
    drawName();
  }

  if (bio) {
    ctx.font = font(500, 34);
    ctx.fillStyle = colors.muted;
    const lines = wrapCanvasText(ctx, bio, 980, 2);
    lines.forEach((line, i) => ctx.fillText(line, 600, bioY + i * 46));
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
