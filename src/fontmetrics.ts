import { fontFileUrl } from "./theme";
import { LoadedFont, LoadedFontMetrics } from "./types";

// Vertical metrics straight out of a TTF/OTF binary: unitsPerEm from `head`,
// ascender/descender/lineGap from `hhea` — the values line layout uses, and
// the ones the fallback face's *-override descriptors need to match.
export function parseFontMetrics(
  buf: ArrayBuffer,
): LoadedFontMetrics | undefined {
  try {
    const dv = new DataView(buf);
    // A collection ('ttcf') indexes whole fonts; metrics come from the first.
    const base = dv.getUint32(0) === 0x74746366 ? dv.getUint32(12) : 0;
    const numTables = dv.getUint16(base + 4);
    let head = -1;
    let hhea = -1;
    for (let i = 0; i < numTables; i++) {
      const rec = base + 12 + i * 16;
      const tag = String.fromCharCode(
        dv.getUint8(rec),
        dv.getUint8(rec + 1),
        dv.getUint8(rec + 2),
        dv.getUint8(rec + 3),
      );
      if (tag === "head") head = dv.getUint32(rec + 8);
      if (tag === "hhea") hhea = dv.getUint32(rec + 8);
    }
    if (head < 0 || hhea < 0) return undefined;
    const upm = dv.getUint16(head + 18);
    const ascent = dv.getInt16(hhea + 4);
    const descent = dv.getInt16(hhea + 6);
    const lineGap = dv.getInt16(hhea + 8);
    return upm > 0 && ascent > 0
      ? { upm, ascent, descent, lineGap }
      : undefined;
  } catch {
    return undefined;
  }
}

// The font with metrics measured from its regular face — or unchanged when
// the file can't be fetched or parsed; the fallback then simply stays
// unmatched, as it was before metrics existed.
export async function measureLoadedFont(font: LoadedFont): Promise<LoadedFont> {
  if (font.metrics) return font;
  const face = font.faces.find((f) => !f.italic) ?? font.faces[0];
  if (!face) return font;
  try {
    const res = await fetch(fontFileUrl(font.slug, face.file));
    if (!res.ok) return font;
    const metrics = parseFontMetrics(await res.arrayBuffer());
    return metrics ? { ...font, metrics } : font;
  } catch {
    return font;
  }
}
