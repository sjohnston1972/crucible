/* Minimal ZIP writer (STORE / no compression).
 *
 * Replaces the JSZip dependency from the spec: config templates are small text
 * files, so uncompressed STORE entries keep the tool a single dependency-free
 * bundle. Returns a Uint8Array; the caller wraps it in a Blob to download.
 */

const textEncoder = new TextEncoder();

// Standard CRC-32 (polynomial 0xEDB88320), table built once.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

class ByteWriter {
  constructor() {
    this.chunks = [];
    this.length = 0;
  }
  u16(v) {
    this.chunks.push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff]));
    this.length += 2;
  }
  u32(v) {
    this.chunks.push(
      new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff])
    );
    this.length += 4;
  }
  bytes(b) {
    this.chunks.push(b);
    this.length += b.length;
  }
  concat() {
    const out = new Uint8Array(this.length);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

/**
 * Build a zip from [{ path, content }] (content = string).
 * Returns a Uint8Array.
 */
export function buildZip(files) {
  const w = new ByteWriter();
  const central = [];

  for (const file of files) {
    const nameBytes = textEncoder.encode(file.path.replace(/\\/g, "/"));
    const dataBytes =
      typeof file.content === "string" ? textEncoder.encode(file.content) : file.content;
    const crc = crc32(dataBytes);
    const offset = w.length;

    // local file header
    w.u32(0x04034b50);
    w.u16(20); // version needed
    w.u16(0x0800); // flags: UTF-8 filename
    w.u16(0); // method: store
    w.u16(0); // mod time (fixed — Date may be unavailable in some runtimes)
    w.u16(0x21); // mod date (fixed: 1980-01-01)
    w.u32(crc);
    w.u32(dataBytes.length); // compressed size
    w.u32(dataBytes.length); // uncompressed size
    w.u16(nameBytes.length);
    w.u16(0); // extra length
    w.bytes(nameBytes);
    w.bytes(dataBytes);

    central.push({ nameBytes, crc, size: dataBytes.length, offset });
  }

  // central directory
  const cdStart = w.length;
  for (const e of central) {
    w.u32(0x02014b50);
    w.u16(20); // version made by
    w.u16(20); // version needed
    w.u16(0x0800); // flags
    w.u16(0); // method
    w.u16(0); // mod time
    w.u16(0x21); // mod date
    w.u32(e.crc);
    w.u32(e.size);
    w.u32(e.size);
    w.u16(e.nameBytes.length);
    w.u16(0); // extra
    w.u16(0); // comment
    w.u16(0); // disk number start
    w.u16(0); // internal attrs
    w.u32(0); // external attrs
    w.u32(e.offset);
    w.bytes(e.nameBytes);
  }
  const cdSize = w.length - cdStart;

  // end of central directory
  w.u32(0x06054b50);
  w.u16(0);
  w.u16(0);
  w.u16(central.length);
  w.u16(central.length);
  w.u32(cdSize);
  w.u32(cdStart);
  w.u16(0); // comment length

  return w.concat();
}
