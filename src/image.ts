import {
  avatarImageSrc,
  clampCoverHeight,
  clampZoom,
  linkIconMaxRawBytes,
  sanitizeObjectPosition,
} from "./theme";
import { t } from "./i18n";
import { CompressedAvatar, LinkTree } from "./types";
import { subtle } from "./util";

export function canvasToBlob(
  canvas: HTMLCanvasElement,
  mime: CompressedAvatar["mime"],
  quality: number,
): Promise<Blob | null> {
  return new Promise((resolve) => {
    canvas.toBlob(resolve, mime, quality);
  });
}

export function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(String(reader.result)));
    reader.addEventListener("error", () => reject(reader.error));
    reader.readAsDataURL(blob);
  });
}

export async function loadImageForCanvas(
  file: File,
): Promise<CanvasImageSource> {
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

export async function compressAvatar(file: File): Promise<CompressedAvatar> {
  // Keep the whole image (downscaled) so the region shown in the round frame
  // can be chosen by dragging, rather than baked in at upload.
  return compressImage(file, 640, 640, "contain");
}

export async function compressCover(file: File): Promise<CompressedAvatar> {
  // Keep the whole image (downscaled) so the region shown in the banner can be
  // chosen later by dragging, rather than baked in at upload.
  return compressImage(file, 1400, 1400, "contain");
}

export async function compressBg(file: File): Promise<CompressedAvatar> {
  return compressImage(file, 1600, 1600, "contain");
}

// Custom social preview image: center-cropped to the 1200×630 og:image canvas
// and encoded as JPEG (not AVIF — link scrapers are conservative).
export async function compressOgImage(file: File): Promise<string> {
  const image = await loadImageForCanvas(file);
  const sourceWidth = Number("width" in image ? image.width : 0);
  const sourceHeight = Number("height" in image ? image.height : 0);
  if (!sourceWidth || !sourceHeight) {
    throw new Error(t("Could not read that image."));
  }
  const canvas = document.createElement("canvas");
  canvas.width = 1200;
  canvas.height = 630;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error(t("Could not prepare the image."));
  }
  const scale = Math.max(1200 / sourceWidth, 630 / sourceHeight);
  const cropWidth = Math.round(1200 / scale);
  const cropHeight = Math.round(630 / scale);
  const sx = Math.floor((sourceWidth - cropWidth) / 2);
  const sy = Math.floor((sourceHeight - cropHeight) / 2);
  ctx.drawImage(image, sx, sy, cropWidth, cropHeight, 0, 0, 1200, 630);
  if (image instanceof ImageBitmap) {
    image.close();
  }
  const blob = await canvasToBlob(canvas, "image/jpeg", 0.85);
  if (!blob) {
    throw new Error(t("Could not compress that image."));
  }
  return blobToDataUrl(blob);
}

// Encodes as AVIF (falling back to JPEG). "cover" center-crops to fill the
// target box; "contain" downscales the whole image to fit within it.
export async function compressImage(
  file: File,
  maxWidth: number,
  maxHeight: number,
  fit: "cover" | "contain",
): Promise<CompressedAvatar> {
  const image = await loadImageForCanvas(file);
  const sourceWidth = Number("width" in image ? image.width : 0);
  const sourceHeight = Number("height" in image ? image.height : 0);
  if (!sourceWidth || !sourceHeight) {
    throw new Error(t("Could not read that image."));
  }

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error(t("Could not prepare the image."));
  }

  if (fit === "contain") {
    const scale = Math.min(maxWidth / sourceWidth, maxHeight / sourceHeight, 1);
    canvas.width = Math.round(sourceWidth * scale);
    canvas.height = Math.round(sourceHeight * scale);
    ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
  } else {
    const scale = Math.max(maxWidth / sourceWidth, maxHeight / sourceHeight);
    const cropWidth = Math.round(maxWidth / scale);
    const cropHeight = Math.round(maxHeight / scale);
    const sourceX = Math.floor((sourceWidth - cropWidth) / 2);
    const sourceY = Math.floor((sourceHeight - cropHeight) / 2);
    canvas.width = maxWidth;
    canvas.height = maxHeight;
    ctx.drawImage(
      image,
      sourceX,
      sourceY,
      cropWidth,
      cropHeight,
      0,
      0,
      maxWidth,
      maxHeight,
    );
  }
  if (image instanceof ImageBitmap) {
    image.close();
  }

  return encodeCanvas(canvas);
}

export async function encodeCanvas(
  canvas: HTMLCanvasElement,
): Promise<CompressedAvatar> {
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
  throw new Error(t("Could not compress that image."));
}

// Splits a base64 data: URL into a subresource {mime, bytes}.
export function dataUrlToSub(
  dataUrl: string,
): { mime: string; bytes: Uint8Array } | null {
  const m = dataUrl.match(/^data:([^;,]+)[^,]*;base64,(.*)$/s);
  if (!m) return null;
  const bin = atob(m[2]);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return { mime: m[1], bytes };
}

export async function subVersion(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await subtle.digest("SHA-256", bytes.slice()));
  return Array.from(digest.slice(0, 4), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

export function loadImageFromSrc(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error(t("Could not read the image.")));
    image.src = src;
  });
}

// Bakes the final crop: renders the exact visible rectangle (object-fit cover +
// focal point + zoom) of the source into a fixed target box and re-encodes, so
// the published image is the cropped pixels — independent of screen width.
export async function bakeCrop(
  src: string,
  targetWidth: number,
  targetHeight: number,
  pos: string,
  zoom: number,
): Promise<string> {
  const image = await loadImageFromSrc(src);
  const sw = image.naturalWidth;
  const sh = image.naturalHeight;
  if (!sw || !sh) return src;
  const coverScale = Math.max(targetWidth / sw, targetHeight / sh);
  const eff = coverScale * clampZoom(zoom);
  const vw = targetWidth / eff;
  const vh = targetHeight / eff;
  const [pxNum, pyNum] = sanitizeObjectPosition(pos)
    .replace(/%/g, "")
    .split(/\s+/)
    .map(Number);
  const sx = Math.max(0, Math.min(sw - vw, (pxNum / 100) * (sw - vw)));
  const sy = Math.max(0, Math.min(sh - vh, (pyNum / 100) * (sh - vh)));
  const canvas = document.createElement("canvas");
  canvas.width = targetWidth;
  canvas.height = targetHeight;
  const ctx = canvas.getContext("2d");
  if (!ctx) return src;
  ctx.drawImage(image, sx, sy, vw, vh, 0, 0, targetWidth, targetHeight);
  return (await encodeCanvas(canvas)).dataUrl;
}

// Returns a copy of the tree with the avatar and (filled) cover replaced by
// their baked crops and the crop controls neutralized — what gets published.
// The untouched source stays in `priv` for later re-cropping.
export async function bakeTreeImages(tree: LinkTree): Promise<LinkTree> {
  const next: LinkTree = { ...tree };
  const avatar = avatarImageSrc(tree.avatarUrl);
  if (avatar) {
    next.avatarUrl = await bakeCrop(
      avatar,
      256,
      256,
      sanitizeObjectPosition(tree.avatarPos),
      clampZoom(tree.avatarZoom),
    );
    next.avatarPos = "50% 50%";
    next.avatarZoom = 1;
  }
  const cover = avatarImageSrc(tree.coverUrl);
  if (cover && tree.coverFit !== "contain") {
    const h = clampCoverHeight(tree.coverHeight);
    next.coverUrl = await bakeCrop(
      cover,
      880,
      Math.round((880 * h) / 440),
      sanitizeObjectPosition(tree.coverPos),
      clampZoom(tree.coverZoom),
    );
    next.coverPos = "50% 50%";
    next.coverZoom = 1;
  }
  return next;
}

export function canImportLinkIcon(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

export async function reencodeLinkIcon(blob: Blob): Promise<string> {
  const image = await loadImageForCanvas(
    new File([blob], "icon", { type: blob.type }),
  );
  const sourceWidth = Number("width" in image ? image.width : 0);
  const sourceHeight = Number("height" in image ? image.height : 0);
  if (!sourceWidth || !sourceHeight) {
    throw new Error(t("Could not read that icon."));
  }
  const scale = Math.min(1, 64 / Math.max(sourceWidth, sourceHeight));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(sourceWidth * scale));
  canvas.height = Math.max(1, Math.round(sourceHeight * scale));
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error(t("Could not prepare the icon."));
  }
  ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
  if (image instanceof ImageBitmap) {
    image.close();
  }
  const png = await new Promise<Blob | null>((resolve) => {
    canvas.toBlob(resolve, "image/png");
  });
  if (!png) {
    throw new Error(t("Could not prepare the icon."));
  }
  return blobToDataUrl(png);
}

export async function importLinkIcon(href: string): Promise<string> {
  const response = await fetch(
    `https://cc.me/icon?url=${encodeURIComponent(href)}`,
  );
  if (response.status === 404) {
    throw new Error(t("No icon found for that site."));
  }
  if (!response.ok) {
    throw new Error(
      t("Icon lookup failed ({status}).", { status: String(response.status) }),
    );
  }
  const blob = await response.blob();
  if (!blob.type.startsWith("image/")) {
    throw new Error(t("That site did not return an icon."));
  }
  if (blob.type === "image/svg+xml") {
    if (blob.size > linkIconMaxRawBytes) {
      throw new Error(t("That icon is too large."));
    }
    return blobToDataUrl(blob);
  }
  try {
    return await reencodeLinkIcon(blob);
  } catch {
    if (blob.size <= linkIconMaxRawBytes) {
      return blobToDataUrl(blob);
    }
    throw new Error(t("Could not read that icon."));
  }
}
