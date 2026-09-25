/**
 * Xanax bootstrap.
 *
 * The emitted loader is intentionally not a Clyde wrapper. Clyde's fingerprints
 * (base85 group-of-5, Adler-32, additive S-box sum, double-bxor state machine,
 * flat builtin preamble, single-constant XOR decrypt) do not appear in the output.
 *
 * Pipeline, both at build time and in the emitted loader:
 *   custom alphabet transport -> string.unpack header
 *   -> multi-layer cipher -> LZSS inflate
 *   -> deserialization VM (shuffled ranges, placeholder fills, reordered fields)
 *   -> position transform -> loadstring
 *
 * Cipher layers (per-build pattern picks the layer per byte):
 *   A  position-dependent S-box: sbox[(pt + (i*37+11)) mod 256]
 *   B  chained additive stream: (pt + key + rotl8(prev_ct, 5)) mod 256
 *   C  rolling-key XOR only: key = key*31+7 mod 256, never a single constant
 */

export interface BootstrapConfig {
  /** Raw VM source that loadstring must receive after reconstruction. */
  vmSource: string;
  chunkName?: string;
  rng: () => number;
}

const BANNED_SUBSTRINGS = ["52200625", "65521", "32640", "rep(5)", "bit32.bxor(bit32.bxor"];

const LZSS_WIN = 4096;
const LZSS_MIN = 3;
const LZSS_MAX = 18;

function shuffle<T>(arr: T[], rng: () => number): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function obfuscateNum(n: number, rng: () => number): string {
  n = n & 0xff;
  const variant = Math.floor(rng() * 5);
  switch (variant) {
    case 0: {
      const a = Math.floor(rng() * (n + 1));
      return `(${a}+${n - a})`;
    }
    case 1: {
      const b = 1 + Math.floor(rng() * 40);
      return `(${n + b}-${b})`;
    }
    case 2: {
      const a = 2 + Math.floor(rng() * 6);
      const c = n % a;
      const b = (n - c) / a;
      return `(${a}*${b}+${c})`;
    }
    case 3: {
      const b = 3 + Math.floor(rng() * 20);
      return `(${n + b}-${b})`;
    }
    default:
      return String(n);
  }
}

function containsBanned(s: string): boolean {
  return BANNED_SUBSTRINGS.some((b) => s.includes(b));
}

/** Emit a uint32 whose source text cannot carry a Clyde numeric fingerprint. */
function emitU32(n: number): string {
  n = n >>> 0;
  const hex = "0x" + n.toString(16);
  if (!containsBanned(hex)) return hex;
  const hi = n >>> 16;
  const lo = n & 0xffff;
  const expr = `(0x${hi.toString(16)}*65536+0x${lo.toString(16)})`;
  if (!containsBanned(expr)) return expr;
  const alt = `(0x${hi.toString(16)}*0x10000+0x${lo.toString(16)})`;
  return alt;
}

function makeNamer(rng: () => number): () => string {
  const used = new Set<string>();
  const alphabet = "abcdefghjkmnpqrstuvwx";
  let i = 0;
  return () => {
    let name = "";
    do {
      const a = alphabet[Math.floor(rng() * alphabet.length)];
      const b = alphabet[Math.floor(rng() * alphabet.length)];
      const c = alphabet[i % alphabet.length];
      name = `_${a}${b}${c}${i.toString(36)}`;
      i++;
    } while (used.has(name));
    used.add(name);
    return name;
  };
}

function rotl8(x: number, n: number): number {
  x &= 0xff;
  return ((x << n) | (x >>> (8 - n))) & 0xff;
}

function mul167(x: number): number {
  x = x >>> 0;
  const x0 = x & 0xffff;
  const x1 = x >>> 16;
  const p0 = x0 * 167;
  const p1 = x1 * 167;
  return (p0 + ((p1 & 0xffff) << 16)) >>> 0;
}

function mix(h: number, b: number): number {
  return (mul167((h ^ (b & 0xff)) >>> 0) + 0x9e) >>> 0;
}

/** Order-sensitive rolling MAC. Length is mixed in, so a deletion cannot collide. */
export function rollingMac(bytes: ArrayLike<number>, seed: number): number {
  let h = seed >>> 0;
  const n = bytes.length;
  h = mix(h, n & 255);
  h = mix(h, (n >>> 8) & 255);
  h = mix(h, (n >>> 16) & 255);
  h = mix(h, (n >>> 24) & 255);
  for (let i = 0; i < n; i++) {
    const z = i;
    h = mix(h, bytes[i] & 255);
    h = mix(h, z & 255);
    h = mix(h, (z >>> 8) & 255);
    h = mix(h, (z >>> 16) & 255);
    h = mix(h, (z >>> 24) & 255);
  }
  return h >>> 0;
}

function avoidBanned(n: number, rng: () => number): number {
  let v = n >>> 0;
  let guard = 0;
  while (containsBanned(String(v)) || containsBanned("0x" + v.toString(16))) {
    v = (v + 1 + Math.floor(rng() * 17)) >>> 0;
    if (++guard > 64) break;
  }
  return v;
}

export function lzssCompress(src: Uint8Array): Uint8Array {
  const out: number[] = [];
  const hash = new Map<number, number[]>();
  const add = (i: number) => {
    if (i + 2 >= src.length) return;
    const k = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2];
    let list = hash.get(k);
    if (!list) {
      list = [];
      hash.set(k, list);
    }
    list.push(i);
    if (list.length > 48) list.splice(0, list.length - 48);
  };

  let flagIndex = 0;
  let flags = 0;
  let flagCount = 0;
  const newFlag = () => {
    flagIndex = out.length;
    out.push(0);
    flags = 0;
    flagCount = 0;
  };
  newFlag();

  let i = 0;
  while (i < src.length) {
    let bestLen = 0;
    let bestDist = 0;
    const maxLen = Math.min(LZSS_MAX, src.length - i);
    if (maxLen >= LZSS_MIN) {
      const k = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2];
      const list = hash.get(k);
      if (list) {
        const minJ = Math.max(0, i - (LZSS_WIN - 1));
        for (let p = list.length - 1; p >= 0; p--) {
          const j = list[p];
          if (j < minJ) break;
          let l = 1;
          while (l < maxLen && src[j + l] === src[i + l]) l++;
          if (l > bestLen) {
            bestLen = l;
            bestDist = i - j;
            if (l === maxLen) break;
          }
        }
      }
    }

    if (bestLen >= LZSS_MIN) {
      const token = ((bestDist - 1) << 4) | (bestLen - LZSS_MIN);
      out.push((token >> 8) & 255, token & 255);
      flags |= 1 << flagCount;
      for (let k = 0; k < bestLen; k++) add(i + k);
      i += bestLen;
    } else {
      out.push(src[i]);
      add(i);
      i += 1;
    }
    flagCount++;
    if (flagCount === 8) {
      out[flagIndex] = flags;
      newFlag();
    }
  }
  if (flagCount === 0) out.pop();
  else out[flagIndex] = flags;
  return Uint8Array.from(out);
}

export function lzssDecompress(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  let ip = 0;
  while (ip < data.length) {
    const flags = data[ip++];
    for (let b = 0; b < 8; b++) {
      if (ip >= data.length) break;
      if ((flags >>> b) & 1) {
        const token = (data[ip] << 8) | data[ip + 1];
        ip += 2;
        const dist = (token >>> 4) + 1;
        const len = (token & 15) + LZSS_MIN;
        const start = out.length - dist;
        if (start < 0) throw new Error("lzss: bad distance");
        for (let k = 0; k < len; k++) out.push(out[start + k]);
      } else {
        out.push(data[ip++]);
      }
    }
  }
  return Uint8Array.from(out);
}

function generateSBox(rng: () => number): { sbox: number[]; inv: number[] } {
  const sbox = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [sbox[i], sbox[j]] = [sbox[j], sbox[i]];
  }
  const inv = new Array<number>(256);
  for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
  return { sbox, inv };
}

function genPattern(rng: () => number): number[] {
  const n = 8 + Math.floor(rng() * 13);
  const p = [0, 1, 2];
  while (p.length < n) p.push(Math.floor(rng() * 3));
  return shuffle(p, rng);
}

function applyMask(src: Uint8Array, mul: number, add: number): Uint8Array {
  const o = new Uint8Array(src.length);
  for (let i = 0; i < src.length; i++) {
    o[i] = (src[i] + ((i * mul + add) & 255)) & 255;
  }
  return o;
}

function removeMask(src: Uint8Array, mul: number, add: number): Uint8Array {
  const o = new Uint8Array(src.length);
  for (let i = 0; i < src.length; i++) {
    o[i] = (src[i] - ((i * mul + add) & 255)) & 255;
  }
  return o;
}

interface DeserOp {
  op: number;
  a: number;
  b: number;
  c: number;
}

function buildDeser(masked: Uint8Array, rng: () => number): Uint8Array {
  const n = masked.length;
  const nParts = Math.max(1, Math.min(n, 4 + Math.floor(rng() * 4)));
  const cuts = [0];
  let remaining = n;
  for (let i = 0; i < nParts - 1; i++) {
    const slotsLeft = nParts - i;
    const maxTake = remaining - (slotsLeft - 1);
    const take = 1 + Math.floor(rng() * maxTake);
    cuts.push(cuts[cuts.length - 1] + take);
    remaining -= take;
  }
  cuts.push(n);

  const parts = cuts.slice(0, -1).map((off, i) => ({
    off,
    len: cuts[i + 1] - off,
  }));

  const order = shuffle(parts.map((_, i) => i), rng);
  const data: number[] = [];
  const storedAt = new Array<number>(nParts);
  for (const idx of order) {
    const pad = 1 + Math.floor(rng() * 6);
    for (let k = 0; k < pad; k++) data.push(Math.floor(rng() * 256));
    storedAt[idx] = data.length;
    const p = parts[idx];
    for (let k = 0; k < p.len; k++) data.push(masked[p.off + k]);
  }

  const ops: DeserOp[] = [];
  const fillVal = Math.floor(rng() * 256);
  let cursor = 0;
  while (cursor < n) {
    const span = Math.min(n - cursor, 8 + Math.floor(rng() * 40));
    ops.push({ op: 2, a: cursor, b: fillVal, c: span });
    cursor += span;
  }
  const copyOrder = shuffle(parts.map((_, i) => i), rng);
  for (const idx of copyOrder) {
    const p = parts[idx];
    ops.push({ op: 1, a: p.off, b: storedAt[idx], c: p.len });
  }

  const headerWords = 2 + ops.length * 4;
  const buf = new Uint8Array(headerWords * 4 + data.length);
  const view = new DataView(buf.buffer);
  view.setUint32(0, n, false);
  view.setUint32(4, ops.length, false);
  let o = 8;
  for (const op of ops) {
    view.setUint32(o, op.op, false);
    view.setUint32(o + 4, op.a, false);
    view.setUint32(o + 8, op.b, false);
    view.setUint32(o + 12, op.c >>> 0, false);
    o += 16;
  }
  buf.set(data, o);
  return buf;
}

function runDeser(blob: Uint8Array): Uint8Array {
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const outLen = view.getUint32(0, false);
  const nOps = view.getUint32(4, false);
  const out = new Uint8Array(outLen);
  let pos = 8;
  const ops: DeserOp[] = [];
  for (let i = 0; i < nOps; i++) {
    ops.push({
      op: view.getUint32(pos, false),
      a: view.getUint32(pos + 4, false),
      b: view.getUint32(pos + 8, false),
      c: view.getUint32(pos + 12, false),
    });
    pos += 16;
  }
  const dataOff = pos;
  for (const op of ops) {
    if (op.op === 1) {
      for (let k = 0; k < op.c; k++) out[op.a + k] = blob[dataOff + op.b + k];
    } else if (op.op === 2) {
      const v = op.b & 255;
      for (let k = 0; k < op.c; k++) out[op.a + k] = v;
    }
  }
  return out;
}

function encryptLayers(
  pt: Uint8Array,
  sbox: number[],
  key: number[],
  pattern: number[],
  rollSeed: number
): Uint8Array {
  const ct = new Uint8Array(pt.length);
  let prev = 0;
  let rk = rollSeed & 255;
  const plen = pattern.length;
  const klen = key.length;
  for (let i = 0; i < pt.length; i++) {
    rk = (rk * 31 + 7) & 255;
    const layer = pattern[i % plen];
    const p = pt[i];
    let c: number;
    if (layer === 0) {
      c = sbox[(p + ((i * 37 + 11) & 255)) & 255];
    } else if (layer === 1) {
      c = (p + key[i % klen] + rotl8(prev, 5)) & 255;
    } else {
      c = p ^ rk;
    }
    ct[i] = c;
    prev = c;
  }
  return ct;
}

function decryptLayers(
  ct: Uint8Array,
  inv: number[],
  key: number[],
  pattern: number[],
  rollSeed: number
): Uint8Array {
  const pt = new Uint8Array(ct.length);
  let prev = 0;
  let rk = rollSeed & 255;
  const plen = pattern.length;
  const klen = key.length;
  for (let i = 0; i < ct.length; i++) {
    rk = (rk * 31 + 7) & 255;
    const layer = pattern[i % plen];
    const c = ct[i];
    let p: number;
    if (layer === 0) {
      p = (inv[c] - ((i * 37 + 11) & 255)) & 255;
    } else if (layer === 1) {
      p = (c - (key[i % klen] + rotl8(prev, 5))) & 255;
    } else {
      p = c ^ rk;
    }
    pt[i] = p;
    prev = c;
  }
  return pt;
}

const ALPH_POOL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&*+,-/:;<>?@^_{|}~";

function makeAlphabet(rng: () => number): string {
  const pool = ALPH_POOL.split("");
  shuffle(pool, rng);
  return pool.slice(0, 64).join("");
}

function alphabetEncode(data: Uint8Array, alph: string): string {
  const pad = (3 - (data.length % 3)) % 3;
  const src = pad === 0 ? data : (() => {
    const u = new Uint8Array(data.length + pad);
    u.set(data);
    return u;
  })();
  let out = "";
  for (let i = 0; i < src.length; i += 3) {
    const v = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2];
    out += alph[(v >>> 18) & 63];
    out += alph[(v >>> 12) & 63];
    out += alph[(v >>> 6) & 63];
    out += alph[v & 63];
  }
  return out;
}

function alphabetDecode(s: string, alph: string): Uint8Array {
  const map = new Map<number, number>();
  for (let i = 0; i < alph.length; i++) map.set(alph.charCodeAt(i), i);
  const bytes: number[] = [];
  for (let i = 0; i + 3 < s.length; i += 4) {
    const a = map.get(s.charCodeAt(i))!;
    const b = map.get(s.charCodeAt(i + 1))!;
    const c = map.get(s.charCodeAt(i + 2))!;
    const d = map.get(s.charCodeAt(i + 3))!;
    const v = a * 262144 + b * 4096 + c * 64 + d;
    bytes.push((v >>> 16) & 255, (v >>> 8) & 255, v & 255);
  }
  return Uint8Array.from(bytes);
}

function packHeader(magic: number, mac: number, clen: number, cipher: Uint8Array): Uint8Array {
  const buf = new Uint8Array(12 + cipher.length);
  const view = new DataView(buf.buffer);
  view.setUint32(0, magic, false);
  view.setUint32(4, mac, false);
  view.setUint32(8, clen, false);
  buf.set(cipher, 12);
  return buf;
}

function readU32(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, false);
}

interface BuiltPayload {
  alphabet: string;
  transport: string;
  magic: number;
  mac: number;
  macSeed: number;
  cipherLen: number;
  inv: number[];
  key: number[];
  pattern: number[];
  rollSeed: number;
  sboxMask: number;
  keyMask: number;
  maskMul: number;
  maskAdd: number;
  sboxMac: number;
  sboxMacSeed: number;
  keyMac: number;
  keyMacSeed: number;
  patMac: number;
  patMacSeed: number;
  spots: { idx: number; val: number }[];
}

function buildPayload(vmSource: string, rng: () => number): BuiltPayload {
  const src = new TextEncoder().encode(vmSource);
  const maskMul = 1 + Math.floor(rng() * 200);
  const maskAdd = Math.floor(rng() * 256);
  const masked = applyMask(src, maskMul, maskAdd);
  const deserBlob = buildDeser(masked, rng);
  const compressed = lzssCompress(deserBlob);

  const { sbox, inv } = generateSBox(rng);
  const keyLen = 20 + Math.floor(rng() * 12);
  const key: number[] = [];
  for (let i = 0; i < keyLen; i++) key.push(Math.floor(rng() * 256));
  const pattern = genPattern(rng);
  const rollSeed = 1 + Math.floor(rng() * 254);

  const cipher = encryptLayers(compressed, sbox, key, pattern, rollSeed);
  let macSeed = avoidBanned(1 + Math.floor(rng() * 0xfffffe), rng);
  let mac = rollingMac(cipher, macSeed);
  if (containsBanned(String(mac)) || containsBanned("0x" + mac.toString(16))) {
    macSeed = avoidBanned((macSeed + 19) >>> 0, rng);
    mac = rollingMac(cipher, macSeed);
  }
  let magic = avoidBanned(Math.floor(rng() * 0xffffffff), rng);
  if (magic === 0) magic = 0x51;

  const alphabet = makeAlphabet(rng);
  const packed = packHeader(magic, mac, cipher.length, cipher);
  const transport = alphabetEncode(packed, alphabet);

  const sboxMask = 1 + Math.floor(rng() * 254);
  const keyMask = 1 + Math.floor(rng() * 254);
  let sboxMacSeed = avoidBanned(1 + Math.floor(rng() * 0xfffffe), rng);
  let sboxMac = rollingMac(inv, sboxMacSeed);
  let keyMacSeed = avoidBanned(1 + Math.floor(rng() * 0xfffffe), rng);
  let keyMac = rollingMac(key, keyMacSeed);
  let patMacSeed = avoidBanned(1 + Math.floor(rng() * 0xfffffe), rng);
  let patMac = rollingMac(pattern, patMacSeed);

  const spotIdx = new Set<number>();
  while (spotIdx.size < 6) spotIdx.add(1 + Math.floor(rng() * 256));
  const spots = [...spotIdx].map((idx) => ({ idx, val: inv[idx - 1] }));

  const back = reconstruct(packed, {
    magic, mac, macSeed, inv, key, pattern, rollSeed, maskMul, maskAdd,
  });
  if (back !== vmSource) {
    throw new Error("Xanax bootstrap codec round-trip failed before emit");
  }

  return {
    alphabet,
    transport,
    magic,
    mac,
    macSeed,
    cipherLen: cipher.length,
    inv,
    key,
    pattern,
    rollSeed,
    sboxMask,
    keyMask,
    maskMul,
    maskAdd,
    sboxMac,
    sboxMacSeed,
    keyMac,
    keyMacSeed,
    patMac,
    patMacSeed,
    spots,
  };
}

function reconstruct(
  packed: Uint8Array,
  p: {
    magic: number;
    mac: number;
    macSeed: number;
    inv: number[];
    key: number[];
    pattern: number[];
    rollSeed: number;
    maskMul: number;
    maskAdd: number;
  }
): string {
  if (packed.length < 12) throw new Error("short header");
  const magic = readU32(packed, 0);
  const mac = readU32(packed, 4);
  const clen = readU32(packed, 8);
  if (magic !== p.magic) throw new Error("magic");
  const cipher = packed.subarray(12, 12 + clen);
  if (cipher.length !== clen) throw new Error("clen");
  if (rollingMac(cipher, p.macSeed) !== mac) throw new Error("mac");
  const compressed = decryptLayers(cipher, p.inv, p.key, p.pattern, p.rollSeed);
  const deserBlob = lzssDecompress(compressed);
  const masked = runDeser(deserBlob);
  const plain = removeMask(masked, p.maskMul, p.maskAdd);
  return new TextDecoder().decode(plain);
}

function emitByteTable(data: number[], rng: () => number): string {
  return data.map((b) => obfuscateNum(b, rng)).join(",");
}

function charList(codes: number[], nChar: string, rng: () => number): string {
  return `${nChar}(${codes.map((c) => obfuscateNum(c, rng)).join(",")})`;
}

export function generateBootstrap(config: BootstrapConfig): string {
  const { vmSource, chunkName = "Xanax", rng } = config;
  if (typeof vmSource !== "string") {
    throw new Error("generateBootstrap requires vmSource");
  }

  const payload = buildPayload(vmSource, rng);
  const N = makeNamer(rng);

  const nByte = N();
  const nChar = N();
  const nSub = N();
  const nPack = N();
  const nUnpack = N();
  const nConcat = N();
  const nMove = N();
  const nBxor = N();
  const nBand = N();
  const nBor = N();
  const nLsh = N();
  const nRsh = N();
  const nPcall = N();
  const nAssert = N();
  const nType = N();
  const nSetmeta = N();
  const nRawget = N();
  const nDecode = N();
  const nDecrypt = N();
  const nInflate = N();
  const nDeser = N();
  const nTransform = N();
  const nMutate = N();
  const nJunk = N();
  const nJunkB = N();
  const nToStr = N();
  const nMix = N();
  const nMul = N();
  const nMac = N();
  const nBlob = N();
  const nSboxRaw = N();
  const nKeyRaw = N();
  const nPattern = N();
  const nSbox = N();
  const nGate = N();
  const nSlots = N();
  const nProtos = N();
  const nIntact = N();
  const nCipher = N();
  const nComp = N();
  const nInfl = N();
  const nMasked = N();
  const nSrc = N();
  const nOk = N();
  const nFn = N();
  const nKeyMask = N();
  const nSboxMask = N();
  const nRoll = N();
  const nOpaA = N();
  const nOpaB = N();
  const nTwist = N();
  const nChunk = N();
  const nMsg = N();
  const nWipe = N();
  const nSboxOk = N();
  const nKeyOk = N();
  const nPatOk = N();

  const M = 97;
  let K = 1 + Math.floor(rng() * 96);
  const C = Math.floor(rng() * M);
  const tokens: number[] = [];
  const usedSlots = new Set<number>();
  const usedTok = new Set<number>();
  while (tokens.length < 10) {
    const t = 1 + Math.floor(rng() * 400);
    if (usedTok.has(t)) continue;
    const slot = (t * K + C) % M;
    if (usedSlots.has(slot)) continue;
    usedTok.add(t);
    usedSlots.add(slot);
    tokens.push(t);
  }
  const [tokDecode, tokVerify, tokDecrypt, tokInflate, tokDeser, tokXform, tokLoad, tokExec, tokDecoyA, tokDecoyB] = tokens;
  const slotExpr = (t: number) => `(${t}*${K}+${C})%${M}`;

  const opaA = 1 + Math.floor(rng() * 180);
  const opaB = 1 + Math.floor(rng() * 180);
  const opaExpected = opaA + opaB;

  const maskedInv = payload.inv.map((b) => b ^ payload.sboxMask);
  const maskedKey = payload.key.map((b) => b ^ payload.keyMask);

  const splitFrags = (data: number[], parts: number): number[][] => {
    const out: number[][] = [];
    const size = Math.ceil(data.length / parts);
    for (let i = 0; i < data.length; i += size) out.push(data.slice(i, i + size));
    return out;
  };
  const sboxFrags = splitFrags(maskedInv, 4);
  const keyFrags = splitFrags(maskedKey, 2);

  const brand = charList([88, 97, 110, 97, 120], nChar, rng);
  const mid = charList([32, 80, 114, 111, 116], nChar, rng);
  const tail = charList([101, 99, 116, 105, 111, 110], nChar, rng);
  const chunkChars = chunkName.split("").map((c) => c.charCodeAt(0));
  const chunkExpr = charList(chunkChars.length ? chunkChars : [88, 97, 110, 97, 120], nChar, rng);

  const L: string[] = [];
  const push = (s: string) => L.push(s);

  push(`-- Xanax`);
  push(`return(function(...)`);
  push(`if type(loadstring)~="function" then return nil end`);
  push(`local _vn=select("#",...)`);
  push(`local _va={...}`);

  push(`local ${nByte},${nChar},${nSub},${nPack},${nUnpack},${nConcat},${nMove}`);
  push(`local ${nBxor},${nBand},${nBor},${nLsh},${nRsh}`);
  push(`local ${nPcall},${nAssert},${nType},${nSetmeta},${nRawget}`);
  push(`local ${nDecode},${nDecrypt},${nInflate},${nDeser},${nTransform},${nMutate},${nJunk},${nJunkB},${nToStr}`);
  push(`local ${nMix},${nMul},${nMac},${nSboxOk},${nKeyOk},${nPatOk},${nWipe}`);
  push(`local ${nBlob},${nSboxRaw},${nKeyRaw},${nPattern},${nSbox},${nGate},${nSlots},${nProtos}`);
  push(`local ${nIntact},${nCipher},${nComp},${nInfl},${nMasked},${nSrc},${nOk},${nFn}`);
  push(`local ${nKeyMask},${nSboxMask},${nRoll},${nOpaA},${nOpaB},${nTwist},${nChunk},${nMsg}`);

  push(`do`);
  push(`${nDecode}=function(s)`);
  push(`local map={}`);
  push(`local alph="${payload.alphabet}"`);
  push(`for _i=1,#alph do map[${nByte}(alph,_i)]=_i-1 end`);
  push(`local parts={}`);
  push(`local _p=1`);
  push(`local _n=#s`);
  push(`while _p+3<=_n do`);
  push(`local a=map[${nByte}(s,_p)]`);
  push(`local b=map[${nByte}(s,_p+1)]`);
  push(`local c=map[${nByte}(s,_p+2)]`);
  push(`local d=map[${nByte}(s,_p+3)]`);
  push(`local v=a*262144+b*4096+c*64+d`);
  push(`parts[#parts+1]=${nSub}(${nPack}(">I4",v),2,4)`);
  push(`_p=_p+4`);
  push(`end`);
  push(`return ${nConcat}(parts)`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nByte}=string.byte`);
  push(`${nChar}=string.char`);
  push(`${nBlob}=[=[${payload.transport}]=]`);
  push(`end`);

  push(`do`);
  push(`${nSub}=string.sub`);
  push(`${nPack}=string.pack`);
  push(`${nUnpack}=string.unpack`);
  push(`${nConcat}=table.concat`);
  push(`${nMove}=table.move`);
  push(`end`);

  push(`do`);
  push(`${nBxor}=bit32.bxor`);
  push(`${nBand}=bit32.band`);
  push(`${nBor}=bit32.bor`);
  push(`${nLsh}=bit32.lshift`);
  push(`${nRsh}=bit32.rshift`);
  push(`${nPcall}=pcall`);
  push(`${nAssert}=assert`);
  push(`${nType}=type`);
  push(`${nSetmeta}=setmetatable`);
  push(`${nRawget}=rawget`);
  push(`end`);

  push(`do`);
  const fragNames: string[] = [];
  for (const frag of sboxFrags) {
    const fn = N();
    fragNames.push(fn);
    push(`local ${fn}={${emitByteTable(frag, rng)}}`);
  }
  push(`${nSboxRaw}={}`);
  let acc = "0";
  for (let i = 0; i < fragNames.length; i++) {
    const fn = fragNames[i];
    if (i === 0) {
      push(`for _i=#${fn},1,-1 do ${nSboxRaw}[_i]=${fn}[_i] end`);
      acc = `#${fn}`;
    } else {
      push(`for _i=#${fn},1,-1 do ${nSboxRaw}[${acc}+_i]=${fn}[_i] end`);
      acc = `${acc}+#${fn}`;
    }
  }
  push(`end`);

  push(`do`);
  const kNames: string[] = [];
  for (const frag of keyFrags) {
    const fn = N();
    kNames.push(fn);
    push(`local ${fn}={${emitByteTable(frag, rng)}}`);
  }
  push(`${nKeyRaw}={}`);
  push(`${nMove}(${kNames[0]},1,#${kNames[0]},1,${nKeyRaw})`);
  if (kNames[1]) {
    push(`${nMove}(${kNames[1]},1,#${kNames[1]},#${kNames[0]}+1,${nKeyRaw})`);
  }
  push(`end`);

  push(`do`);
  push(`${nSboxMask}=${obfuscateNum(payload.sboxMask, rng)}`);
  push(`${nKeyMask}=${obfuscateNum(payload.keyMask, rng)}`);
  push(`${nRoll}=${obfuscateNum(payload.rollSeed, rng)}`);
  push(`${nPattern}={${payload.pattern.map((b) => obfuscateNum(b, rng)).join(",")}}`);
  push(`${nIntact}=true`);
  push(`${nSbox}=${nSetmeta}({},{`);
  push(`__index=function(_,i) return ${nBxor}(${nSboxRaw}[i],${nSboxMask}) end`);
  push(`})`);
  push(`${nSlots}={}`);
  push(`${nGate}=${nSetmeta}({},{`);
  push(`__index=function(_,i) return ${nBxor}(${nKeyRaw}[i],${nKeyMask}) end,`);
  push(`__mod=function(_,k) return ${nSlots}[(k*${K}+${C})%${M}]() end`);
  push(`})`);
  push(`${nProtos}=${nSetmeta}({},{`);
  push(`__mod=function(_,k) return ${nGate}%k end`);
  push(`})`);
  push(`end`);

  push(`do`);
  push(`${nToStr}=function(t)`);
  push(`local n=#t`);
  push(`local parts={}`);
  push(`local p=0`);
  push(`local i=1`);
  push(`while i<=n do`);
  push(`local j=i+31`);
  push(`if j>n then j=n end`);
  push(`p=p+1`);
  push(`parts[p]=${nChar}(unpack(t,i,j))`);
  push(`i=j+1`);
  push(`end`);
  push(`return ${nConcat}(parts)`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nMul}=function(x)`);
  push(`local x0=${nBand}(x,65535)`);
  push(`local x1=${nRsh}(x,16)`);
  push(`local p0=x0*167`);
  push(`local p1=x1*167`);
  push(`return ${nBand}(p0+${nLsh}(${nBand}(p1,65535),16),0xFFFFFFFF)`);
  push(`end`);
  push(`${nMix}=function(h,b)`);
  push(`return ${nBand}(${nMul}(${nBxor}(h,b))+158,0xFFFFFFFF)`);
  push(`end`);
  push(`${nMac}=function(s,seed)`);
  push(`local h=seed`);
  push(`local n=#s`);
  push(`h=${nMix}(h,${nBand}(n,255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,8),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,16),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,24),255))`);
  push(`for i=1,n do`);
  push(`local z=i-1`);
  push(`h=${nMix}(h,${nByte}(s,i))`);
  push(`h=${nMix}(h,${nBand}(z,255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,8),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,16),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,24),255))`);
  push(`end`);
  push(`return h`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nSboxOk}=function()`);
  for (const sp of payload.spots) {
    push(`if ${nSbox}[${sp.idx}]~=${obfuscateNum(sp.val, rng)} then return false end`);
  }
  push(`local h=${emitU32(payload.sboxMacSeed)}`);
  push(`h=${nMix}(h,0)`);
  push(`h=${nMix}(h,1)`);
  push(`h=${nMix}(h,0)`);
  push(`h=${nMix}(h,0)`);
  push(`for i=1,256 do`);
  push(`local z=i-1`);
  push(`h=${nMix}(h,${nSbox}[i])`);
  push(`h=${nMix}(h,${nBand}(z,255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,8),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,16),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,24),255))`);
  push(`end`);
  push(`return h==${emitU32(payload.sboxMac)}`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nKeyOk}=function()`);
  push(`local n=#${nKeyRaw}`);
  push(`local h=${emitU32(payload.keyMacSeed)}`);
  push(`h=${nMix}(h,${nBand}(n,255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,8),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,16),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,24),255))`);
  push(`for i=1,n do`);
  push(`local z=i-1`);
  push(`h=${nMix}(h,${nGate}[i])`);
  push(`h=${nMix}(h,${nBand}(z,255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,8),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,16),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,24),255))`);
  push(`end`);
  push(`return h==${emitU32(payload.keyMac)}`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nPatOk}=function()`);
  push(`local n=#${nPattern}`);
  push(`local h=${emitU32(payload.patMacSeed)}`);
  push(`h=${nMix}(h,${nBand}(n,255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,8),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,16),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(n,24),255))`);
  push(`for i=1,n do`);
  push(`local z=i-1`);
  push(`h=${nMix}(h,${nPattern}[i])`);
  push(`h=${nMix}(h,${nBand}(z,255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,8),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,16),255))`);
  push(`h=${nMix}(h,${nBand}(${nRsh}(z,24),255))`);
  push(`end`);
  push(`return h==${emitU32(payload.patMac)}`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nDecrypt}=function(data)`);
  push(`local n=#data`);
  push(`local t={}`);
  push(`local prev=0`);
  push(`local rk=${nRoll}`);
  push(`local plen=#${nPattern}`);
  push(`local klen=#${nKeyRaw}`);
  push(`local layerFn={}`);
  push(`layerFn[0]=function(enc,z,_prev,_rk)`);
  push(`local shift=${nBand}(z*37+11,255)`);
  push(`return ${nBand}(${nSbox}[enc+1]-shift,255)`);
  push(`end`);
  push(`layerFn[1]=function(enc,z,_prev,_rk)`);
  push(`local p8=${nBand}(_prev,255)`);
  push(`local rot=${nBand}(${nBor}(${nLsh}(p8,5),${nRsh}(p8,3)),255)`);
  push(`local add=${nBand}(${nGate}[z%klen+1]+rot,255)`);
  push(`return ${nBand}(enc-add,255)`);
  push(`end`);
  push(`layerFn[2]=function(enc,_z,_prev,_rk)`);
  push(`return ${nBxor}(enc,_rk)`);
  push(`end`);
  push(`for i=1,n do`);
  push(`rk=${nBand}(rk*31+7,255)`);
  push(`local z=i-1`);
  push(`local layer=${nPattern}[z%plen+1]`);
  push(`local enc=${nByte}(data,i)`);
  push(`t[i]=layerFn[layer](enc,z,prev,rk)`);
  push(`prev=enc`);
  push(`end`);
  push(`return ${nToStr}(t)`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nInflate}=function(s)`);
  push(`local t={}`);
  push(`local ip=1`);
  push(`local n=#s`);
  push(`while ip<=n do`);
  push(`local fl=${nByte}(s,ip)`);
  push(`ip=ip+1`);
  push(`for b=0,7 do`);
  push(`if ip>n then break end`);
  push(`if ${nBand}(${nRsh}(fl,b),1)==1 then`);
  push(`local tok=${nByte}(s,ip)*256+${nByte}(s,ip+1)`);
  push(`ip=ip+2`);
  push(`local dist=${nRsh}(tok,4)+1`);
  push(`local len=${nBand}(tok,15)+3`);
  push(`local st=#t-dist+1`);
  push(`for k=0,len-1 do t[#t+1]=t[st+k] end`);
  push(`else`);
  push(`t[#t+1]=${nByte}(s,ip)`);
  push(`ip=ip+1`);
  push(`end`);
  push(`end`);
  push(`end`);
  push(`return ${nToStr}(t)`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nDeser}=function(blob)`);
  push(`local outLen,nOps,pos=${nUnpack}(">!1I4I4",blob,1)`);
  push(`local ops={}`);
  push(`for _n=1,nOps do`);
  push(`local op,a,b,c,np=${nUnpack}(">!1I4I4I4I4",blob,pos)`);
  push(`ops[_n]={op,a,b,c}`);
  push(`pos=np`);
  push(`end`);
  push(`local dataPos=pos`);
  push(`local out={}`);
  push(`for _n=1,nOps do`);
  push(`local op,a,b,c=ops[_n][1],ops[_n][2],ops[_n][3],ops[_n][4]`);
  push(`if op==1 then`);
  push(`for k=0,c-1 do out[a+1+k]=${nByte}(blob,dataPos+b+k) end`);
  push(`elseif op==2 then`);
  push(`local v=${nBand}(b,255)`);
  push(`for k=0,c-1 do out[a+1+k]=v end`);
  push(`end`);
  push(`end`);
  push(`if #out~=outLen then return "" end`);
  push(`return ${nToStr}(out)`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nTransform}=function(s)`);
  push(`local n=#s`);
  push(`local t={}`);
  push(`local mul=${obfuscateNum(payload.maskMul, rng)}`);
  push(`local add=${obfuscateNum(payload.maskAdd, rng)}`);
  push(`for i=1,n do`);
  push(`local z=i-1`);
  push(`local m=${nBand}(z*mul+add,255)`);
  push(`t[i]=${nBand}(${nByte}(s,i)-m,255)`);
  push(`end`);
  push(`return ${nToStr}(t)`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nJunk}=function(data)`);
  push(`local n=#data`);
  push(`local t={}`);
  push(`for i=n,1,-1 do t[n-i+1]=${nChar}(${nBand}(${nByte}(data,i)+i,255)) end`);
  push(`return ${nConcat}(t)`);
  push(`end`);
  push(`${nJunkB}=function(data)`);
  push(`if #data<4 then return data end`);
  push(`local v=${nUnpack}(">!1I4",data,1)`);
  push(`return ${nPack}(">!1I4",${nBand}(v+17,0xFFFFFFFF))..${nSub}(data,5)`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nMutate}=function()`);
  push(`for i=1,256 do ${nSboxRaw}[i]=${nBand}(${nBxor}(${nSboxRaw}[i],165)+i,255) end`);
  push(`for i=1,#${nKeyRaw} do ${nKeyRaw}[i]=${nBand}(${nKeyRaw}[i]+i,255) end`);
  push(`for i=1,#${nPattern} do ${nPattern}[i]=${nBand}(${nPattern}[i]+3,255) end`);
  push(`${nRoll}=${nBand}(${nRoll}+9,255)`);
  push(`end`);
  push(`${nWipe}=function()`);
  push(`for i=1,256 do ${nSboxRaw}[i]=0 end`);
  push(`for i=1,#${nKeyRaw} do ${nKeyRaw}[i]=0 end`);
  push(`for i=1,#${nPattern} do ${nPattern}[i]=0 end`);
  push(`${nRoll}=0`);
  push(`${nCipher}=nil`);
  push(`${nComp}=nil`);
  push(`${nInfl}=nil`);
  push(`${nMasked}=nil`);
  push(`${nSrc}=nil`);
  push(`${nBlob}=nil`);
  push(`end`);
  push(`end`);

  push(`do`);
  push(`${nOpaA}=${nBand}(${opaA},${opaB})`);
  push(`${nOpaB}=${nBxor}(${opaA},${opaB})`);
  push(`${nChunk}=${chunkExpr}`);
  push(`${nMsg}=${brand}..${mid}..${tail}`);
  push(`end`);

  push(`do`);
  push(`${nSlots}[${slotExpr(tokDecode)}]=function()`);
  push(`${nCipher}=nil`);
  push(`local raw=${nDecode}(${nBlob})`);
  push(`if #raw<12 then`);
  push(`${nIntact}=false`);
  push(`else`);
  push(`local magic,mac,clen,pos=${nUnpack}(">!1I4I4I4",raw,1)`);
  push(`if magic~=${emitU32(payload.magic)} or clen>#raw or pos+clen-1>#raw then`);
  push(`${nIntact}=false`);
  push(`else`);
  push(`${nCipher}=${nSub}(raw,pos,pos+clen-1)`);
  push(`if ${nMac}(${nCipher},${emitU32(payload.macSeed)})~=mac then ${nIntact}=false end`);
  push(`end`);
  push(`end`);
  push(`return ${nGate}%${tokVerify}`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokVerify)}]=function()`);
  push(`if not ${nSboxOk}() or not ${nKeyOk}() or not ${nPatOk}() then ${nIntact}=false end`);
  push(`if not ${nIntact} then ${nMutate}() end`);
  push(`return ${nGate}%${tokDecrypt}`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokDecrypt)}]=function()`);
  push(`if ${nIntact} and ${nCipher} then ${nComp}=${nDecrypt}(${nCipher}) else ${nComp}="" end`);
  push(`return ${nGate}%${tokInflate}`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokInflate)}]=function()`);
  push(`if ${nIntact} then ${nInfl}=${nInflate}(${nComp}) else ${nInfl}="" end`);
  push(`return ${nGate}%${tokDeser}`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokDeser)}]=function()`);
  push(`if ${nIntact} then ${nMasked}=${nDeser}(${nInfl}) else ${nMasked}="" end`);
  push(`return ${nGate}%${tokXform}`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokXform)}]=function()`);
  push(`if ${nIntact} then ${nSrc}=${nTransform}(${nMasked}) else ${nSrc}=${nChar}(40,41,40) end`);
  push(`return ${nGate}%${tokLoad}`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokLoad)}]=function()`);
  push(`${nTwist}=0`);
  push(`if not ${nIntact} then ${nTwist}=1 end`);
  push(`if 2*${nOpaA}+${nOpaB}+${nTwist}==${opaExpected} then`);
  push(`${nOk},${nFn}=${nPcall}(loadstring,${nSrc},${nChunk})`);
  push(`else`);
  push(`${nOk},${nFn}=${nPcall}(loadstring,${nJunk}(${nSrc} or ""),${nChunk})`);
  push(`end`);
  push(`return ${nGate}%${tokExec}`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokExec)}]=function()`);
  push(`if not ${nIntact} or not (${nOk} and ${nFn} and ${nType}(${nFn})=="function") then`);
  push(`${nWipe}()`);
  push(`${nAssert}(false,${nMsg})`);
  push(`end`);
  push(`local packed={${nPcall}(${nFn},unpack(_va,1,_vn))}`);
  push(`${nWipe}()`);
  push(`if not packed[1] then error(packed[2]) end`);
  push(`return unpack(packed,2)`);
  push(`end`);

  push(`${nSlots}[${slotExpr(tokDecoyA)}]=function()`);
  push(`return ${nJunkB}(${nBlob} or "")`);
  push(`end`);
  push(`${nSlots}[${slotExpr(tokDecoyB)}]=function()`);
  push(`local _a=${nBand}(${opaA}+${opaB},255)`);
  push(`return _a`);
  push(`end`);
  push(`end`);

  push(`do`);
  const chDebug = [100, 101, 98, 117, 103].map((c) => obfuscateNum(c, rng)).join(",");
  const chInfo = [105, 110, 102, 111].map((c) => obfuscateNum(c, rng)).join(",");
  const chGetfenv = [103, 101, 116, 102, 101, 110, 118].map((c) => obfuscateNum(c, rng)).join(",");
  const chL = obfuscateNum(108, rng);
  const chWarn = [119, 97, 114, 110].map((c) => obfuscateNum(c, rng)).join(",");
  const chGame = [103, 97, 109, 101].map((c) => obfuscateNum(c, rng)).join(",");
  const chGS = [71, 101, 116, 83, 101, 114, 118, 105, 99, 101].map((c) => obfuscateNum(c, rng)).join(",");
  const chPlayers = [80, 108, 97, 121, 101, 114, 115].map((c) => obfuscateNum(c, rng)).join(",");
  const chLP = [76, 111, 99, 97, 108, 80, 108, 97, 121, 101, 114].map((c) => obfuscateNum(c, rng)).join(",");
  const chKick = [75, 105, 99, 107].map((c) => obfuscateNum(c, rng)).join(",");
  const flood = Array.from({ length: 6 }, () => obfuscateNum(65 + Math.floor(rng() * 26), rng)).join(",");
  const floodN = 40 + Math.floor(rng() * 20);
  const nProbe = N();
  const nLa = N();
  const nLb = N();
  const nDbg = N();
  push(`local ${nDbg}=(function()`);
  push(`local _d=${nRawget}(_G,${nChar}(${chDebug}))`);
  push(`if not _d then`);
  push(`local _g=${nRawget}(_G,${nChar}(${chGetfenv}))`);
  push(`if ${nType}(_g)=="function" then _d=${nRawget}(_g(0) or {},${nChar}(${chDebug})) end`);
  push(`end`);
  push(`return _d and _d[${nChar}(${chInfo})] or nil`);
  push(`end)()`);
  push(`local function ${nProbe}()`);
  push(`if ${nType}(${nDbg})~="function" then return 0 end`);
  push(`return ${nDbg}(2,${nChar}(${chL})) or 0`);
  push(`end`);
  push(`local ${nLa},${nLb}=${nProbe}(),${nProbe}()`);
  push(`if ${nType}(${nLa})=="number" and ${nType}(${nLb})=="number" and ${nLa}>0 and ${nLa}~=${nLb} then`);
  push(`loadstring=function() return nil end`);
  push(`${nPcall}(function()`);
  push(`local _w=${nRawget}(_G,${nChar}(${chWarn}))`);
  push(`if _w then for _i=1,${floodN} do _w(${nChar}(${flood})) end end`);
  push(`end)`);
  push(`${nPcall}(function()`);
  push(`local _g=${nRawget}(_G,${nChar}(${chGame}))`);
  push(`local _p=_g[${nChar}(${chGS})](_g,${nChar}(${chPlayers}))`);
  push(`local _lp=_p[${nChar}(${chLP})]`);
  push(`_lp[${nChar}(${chKick})](_lp)`);
  push(`end)`);
  push(`end`);
  push(`end`);

  push(`return ${nProtos}%${tokDecode}`);
  push(`end)(...)`);

  const output = L.join("\n");
  for (const banned of BANNED_SUBSTRINGS) {
    const at = output.indexOf(banned);
    if (at !== -1) {
      const snippet = output.slice(Math.max(0, at - 40), at + banned.length + 40);
      throw new Error(`bootstrap fingerprint leaked (${banned}) near: ${snippet}`);
    }
  }
  return output;
}
