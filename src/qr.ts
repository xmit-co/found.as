import qrcode from "qrcode-generator";

export interface QrModel {
  dim: number;
  cells: { x: number; y: number }[];
}

export function buildQrModel(value: string): QrModel {
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

export function qrSvgString(value: string, size: string): string {
  const model = buildQrModel(value);
  const rects = model.cells
    .map((cell) => `<rect x="${cell.x}" y="${cell.y}" width="1" height="1"/>`)
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${model.dim} ${model.dim}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${model.dim}" height="${model.dim}" fill="#ffffff"/><g fill="#111111">${rects}</g></svg>`;
}

export function downloadQrPng(value: string, filename: string): void {
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
