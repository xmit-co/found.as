import { normalizePrivate } from "./linktree";
import { Private, Public } from "./types";
import { decode, encode } from "cbor-x";

// A tiny ZIP reader/writer using the platform's deflate, so a page's `priv` and
// exploded `pub` can be exported as a portable archive and re-imported. Only
// what's needed here: a flat list of files, deflate (method 8) or store
// (method 0) on read.

interface ZipFile {
  name: string;
  data: Uint8Array;
}

const ZIP_DATE = 0x21; // 1980-01-01, a valid stand-in (we don't track mtimes)

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    c = crcTable[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function deflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  void writer.write(data as BufferSource);
  void writer.close();
  return drain(cs.readable);
}

async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  void writer.write(data as BufferSource);
  void writer.close();
  return drain(ds.readable);
}

export async function makeZip(files: ZipFile[]): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;

  for (const file of files) {
    const name = enc.encode(file.name);
    const crc = crc32(file.data);
    const comp = await deflateRaw(file.data);

    const local = new Uint8Array(30 + name.length + comp.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true); // version needed
    lv.setUint16(6, 0, true); // flags
    lv.setUint16(8, 8, true); // deflate
    lv.setUint16(10, 0, true); // time
    lv.setUint16(12, ZIP_DATE, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, comp.length, true);
    lv.setUint32(22, file.data.length, true);
    lv.setUint16(26, name.length, true);
    lv.setUint16(28, 0, true); // extra
    local.set(name, 30);
    local.set(comp, 30 + name.length);
    locals.push(local);

    const central = new Uint8Array(46 + name.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0, true);
    cv.setUint16(10, 8, true);
    cv.setUint16(12, 0, true);
    cv.setUint16(14, ZIP_DATE, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, comp.length, true);
    cv.setUint32(24, file.data.length, true);
    cv.setUint16(28, name.length, true);
    cv.setUint32(42, offset, true); // local header offset
    central.set(name, 46);
    centrals.push(central);

    offset += local.length;
  }

  const cdSize = centrals.reduce((n, c) => n + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true); // central directory offset

  const out = new Uint8Array(offset + cdSize + 22);
  let p = 0;
  for (const l of locals) {
    out.set(l, p);
    p += l.length;
  }
  for (const c of centrals) {
    out.set(c, p);
    p += c.length;
  }
  out.set(eocd, p);
  return out;
}

export async function readZip(
  data: Uint8Array,
): Promise<Map<string, Uint8Array>> {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let eocd = -1;
  for (let i = data.length - 22; i >= 0; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("Not a ZIP file.");
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const dec = new TextDecoder();
  const out = new Map<string, Uint8Array>();
  for (let i = 0; i < count; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const compSize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const localOff = dv.getUint32(p + 42, true);
    const name = dec.decode(data.subarray(p + 46, p + 46 + nameLen));
    const lNameLen = dv.getUint16(localOff + 26, true);
    const lExtraLen = dv.getUint16(localOff + 28, true);
    const start = localOff + 30 + lNameLen + lExtraLen;
    const raw = data.subarray(start, start + compSize);
    out.set(name, method === 8 ? await inflateRaw(raw) : raw.slice());
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

function mimeExt(mime: string | undefined): string {
  const map: Record<string, string> = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/avif": "avif",
    "image/gif": "gif",
    "image/svg+xml": "svg",
    "text/html": "html",
    "text/plain": "txt",
    "application/pdf": "pdf",
  };
  if (!mime) return "bin";
  return map[mime] ?? (mime.split("/")[1] || "bin").replace(/[^a-z0-9]/gi, "");
}

// explodePub turns a page's published record into a directory of files:
// index.html (or the raw bytes / a redirect note) plus each subresource.
export function explodePub(pub: Public): ZipFile[] {
  const files: ZipFile[] = [];
  const enc = new TextEncoder();
  if (pub.html) {
    files.push({ name: "pub/index.html", data: enc.encode(pub.html) });
  } else if (pub.redir) {
    files.push({ name: "pub/redirect.txt", data: enc.encode(pub.redir) });
  } else if (pub.bytes) {
    files.push({ name: `pub/index.${mimeExt(pub.mime)}`, data: pub.bytes });
  }
  for (const [name, sub] of Object.entries(pub.subs ?? {})) {
    files.push({ name: `pub/${name}.${mimeExt(sub.mime)}`, data: sub.bytes });
  }
  return files;
}

export async function exportBackupZip(
  priv: Private,
  pub: Public,
): Promise<Blob> {
  const files: ZipFile[] = [
    { name: "priv.cbor", data: new Uint8Array(encode(priv)) },
    ...explodePub(pub),
  ];
  return new Blob([(await makeZip(files)) as BlobPart], {
    type: "application/zip",
  });
}

// readPrivFromBackup reads only `priv` — from a backup ZIP, or a bare priv.cbor.
export async function readPrivFromBackup(data: Uint8Array): Promise<Private> {
  let privBytes: Uint8Array | undefined;
  if (data[0] === 0x50 && data[1] === 0x4b) {
    const entries = await readZip(data);
    privBytes =
      entries.get("priv.cbor") ??
      [...entries].find(([name]) => name.endsWith("priv.cbor"))?.[1];
  } else {
    privBytes = data; // a bare priv.cbor
  }
  if (!privBytes) {
    throw new Error("No priv.cbor found in this file.");
  }
  return normalizePrivate(decode(privBytes));
}
