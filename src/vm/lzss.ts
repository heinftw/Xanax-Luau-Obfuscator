/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/lzss.ts
 * PART 1 / STEP 10.5 : COMPRESSION BEFORE THE CIPHER
 * ----------------------------------------------------------------------------
 * Pipeline becomes:
 *
 *   base85 -> LZSS decompress -> Speck32/whitening decrypt
 *          -> deserialization VM -> Real VM
 *
 * Why LZSS and not the existing lzma.ts: lzma.ts calls zlib's deflateRawSync,
 * which is fine for producing the blob but useless at runtime because Luau
 * has no inflate.  LZSS decompresses in ~30 lines of plain Luau, so the
 * decoder ships inside the bootstrap and can be split across fragments.
 *
 * Format (little endian; Luau side is 1-based):
 *   flag byte F
 *     bit b (b = 0..7):
 *       0 -> literal byte follows
 *       1 -> 16-bit token:  dist = (token >> 4) + 1   (1..4095)
 *                             len = (token & 15) + 3   (3..18)
 * ==========================================================================*/

export const LZSS_WINDOW = 4096;
export const LZSS_MIN_MATCH = 3;
export const LZSS_MAX_MATCH = 18;

export interface LzssResult {
  data: Uint8Array;
  original: number;
  ratio: number;
}

/** Compress.  Greedy, brute-force window search - fast enough at build time. */
export function lzssCompress(src: Uint8Array): LzssResult {
  const out: number[] = [];
  let flagIndex = 0;
  let flags = 0;
  let flagCount = 0;

  const newFlagByte = () => {
    flagIndex = out.length;
    out.push(0);
    flags = 0;
    flagCount = 0;
  };
  newFlagByte();

  let i = 0;
  while (i < src.length) {
    let bestLen = 0;
    let bestDist = 0;
    const maxLen = Math.min(LZSS_MAX_MATCH, src.length - i);

    if (maxLen >= LZSS_MIN_MATCH) {
      const start = Math.max(0, i - (LZSS_WINDOW - 1));
      for (let j = start; j < i; j++) {
        if (src[j] !== src[i]) continue;
        let l = 1;
        while (l < maxLen && src[j + l] === src[i + l]) l++;
        if (l > bestLen) {
          bestLen = l;
          bestDist = i - j;
          if (l === maxLen) break;
        }
      }
    }

    if (bestLen >= LZSS_MIN_MATCH) {
      const token = (((bestDist - 1) & 0xfff) << 4) | (bestLen - LZSS_MIN_MATCH);
      out.push((token >> 8) & 0xff, token & 0xff);
      flags |= 1 << flagCount;
      i += bestLen;
    } else {
      out.push(src[i]);
      i += 1;
    }

    flagCount++;
    if (flagCount === 8) {
      out[flagIndex] = flags;
      newFlagByte();
    }
  }

  if (flagCount === 0) out.pop();
  else out[flagIndex] = flags;

  const data = new Uint8Array(out);
  return {
    data,
    original: src.length,
    ratio: src.length === 0 ? 1 : data.length / src.length,
  };
}

/** Reference decompressor - mirrors the emitted Luau exactly. */
export function lzssDecompress(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  let ip = 0;
  while (ip < data.length) {
    const flags = data[ip++];
    for (let b = 0; b < 8; b++) {
      if (ip >= data.length) break;
      if ((flags >> b) & 1) {
        const token = (data[ip] << 8) | data[ip + 1];
        ip += 2;
        const dist = (token >> 4) + 1;
        const len = (token & 15) + LZSS_MIN_MATCH;
        const start = out.length - dist;
        if (start < 0) throw new Error('Xanax/lzss: corrupt stream (dist > produced)');
        for (let k = 0; k < len; k++) out.push(out[start + k]);
      } else {
        out.push(data[ip++]);
      }
    }
  }
  return new Uint8Array(out);
}

/** Round-trip self check for real_check-script. */
export function roundTripLzss(payload: Uint8Array): boolean {
  const c = lzssCompress(payload);
  const d = lzssDecompress(c.data);
  if (d.length !== payload.length) return false;
  for (let i = 0; i < payload.length; i++) if (d[i] !== payload[i]) return false;
  return true;
}

/* ==========================================================================
 * LUAU EMISSION
 * ========================================================================*/

export interface LzssEmitCtx {
  nm: (hint: string) => string;
  nByte: string;
  nChar: string;
  nTconcat: string;
  nBand: string;
  nRshift: string;
  /** name of the local holding the compressed payload as a string */
  nPayload: string;
}

/**
 * Emit a Luau function that inflates `nPayload` back into a plaintext string.
 * `nPayload` is the local produced by emitLzssPayloadLua.
 */
export function emitLzssDecompressorLua(ctx: LzssEmitCtx): { name: string; code: string } {
  const { nm, nByte, nChar, nTconcat, nBand, nRshift, nPayload } = ctx;
  const fn = nm('inflate');
  const ip = nm('ip');
  const fl = nm('fl');
  const b = nm('b');
  const tk = nm('tk');
  const ds = nm('ds');
  const ln = nm('ln');
  const st = nm('st');
  const t = nm('t');

  return {
    name: fn,
    code: [
    '-- LZSS inflate (STEP 10.5): runs after the cipher, inside the bootstrap',
    'local function ' + fn + '(' + nPayload + ')',
    ' local ' + t + '={}',
    ' local ' + ip + '=1',
    ' while ' + ip + '<=#' + nPayload + ' do',
    '  local ' + fl + '=' + nByte + '(' + nPayload + ',' + ip + ')',
    '  ' + ip + '=' + ip + '+1',
    '  for ' + b + '=0,7 do',
    '   if ' + ip + '>#' + nPayload + ' then break end',
    '   if ' + nBand + '(' + nRshift + '(' + fl + ',' + b + '),1)==1 then',
    '    local ' + tk + '=' + nByte + '(' + nPayload + ',' + ip + ')*256+' + nByte + '(' + nPayload + ',' + ip + '+1)',
    '    ' + ip + '=' + ip + '+2',
    '    local ' + ds + '=' + nRshift + '(' + tk + ',4)+1',
    '    local ' + ln + '=' + nBand + '(' + tk + ',15)+' + LZSS_MIN_MATCH,
    '    local ' + st + '=#' + t + '-' + ds + '+1',
    '    for _0k=0,' + ln + '-1 do ' + t + '[#' + t + '+1]=' + t + '[' + st + '+_0k] end',
    '   else',
    '    ' + t + '[#' + t + '+1]=' + nChar + '(' + nByte + '(' + nPayload + ',' + ip + '))',
    '    ' + ip + '=' + ip + '+1',
    '   end',
    '  end',
    ' end',
    ' return ' + nTconcat + '(' + t + ')',
    'end',
    ].join('\n'),
  };
}

/**
 * Emit the compressed payload as Luau locals.
 *
 * Every chunk is a `string.char(...)` call rather than a literal, so the bytes
 * never appear as readable text, and the final blob is a table.concat over an
 * arbitrary number of locals - there is no single literal an attacker can
 * lift.  The number of chunks is randomised by `chunkSize`.
 */
export function emitLzssPayloadLua(
  nm: (hint: string) => string,
  nChar: string,
  nTconcat: string,
  data: Uint8Array,
  chunkSize = 96
): { name: string; code: string } {
  const name = nm('lzblob');
  if (data.length === 0) {
    return { name, code: 'local ' + name + '=""' };
  }

  const names: string[] = [];
  const body: string[] = [];
  for (let i = 0; i < data.length; i += chunkSize) {
    const pn = nm('lz');
    names.push(pn);
    const hi = Math.min(data.length, i + chunkSize);
    const args: string[] = [];
    for (let k = i; k < hi; k++) args.push(String(data[k]));
    body.push('local ' + pn + '=' + nChar + '(' + args.join(',') + ')');
  }

  body.push('local ' + name + '=' + nTconcat + '({' + names.join(',') + '},"")');
  return { name, code: body.join('\n') };
}
