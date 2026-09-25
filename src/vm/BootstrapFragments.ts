/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/BootstrapFragments.ts
 * PART 1 / STEP 10 : BOOTSTRAP JUNK LAYERING + COMPRESSION
 * ----------------------------------------------------------------------------
 * Stock generateBootstrap() is LINEAR and every section is identifiable:
 *
 *   builtins -> env -> keys -> Speck -> decoder -> decrypt -> anti-debug
 *            -> CFF -> exec
 *
 * New behaviour:
 *   1. The bootstrap is split into 8..12 INDEPENDENT fragments.  Each one
 *      declares its own locals/functions and reads names produced by other
 *      fragments (forward references resolved by the dependency graph).
 *   2. Fragment emission order is a randomised topological sort over that
 *      graph, so the order is different on every build and a reader cannot
 *      tell which fragment is "the decryptor".
 *   3. 3-4 JUNK fragments (arithmetic + string.byte chains) feed junk vars
 *      that later fragments genuinely read, so they are not dead code and
 *      cannot be removed by a DCE pass.
 *   4. Key derivation, the base85 decoder and the cipher are each split
 *      across separate fragments.
 *   5. LZSS compression happens BEFORE the cipher:
 *          base85 -> LZSS inflate -> cipher decrypt -> deser VM -> Real VM
 *   6. Anti-simplification: redundant assignments (x=y then x=x+0), if-true
 *      blocks, and algebraic identities a simplifier cannot legally remove.
 *   7. The blob ships as a Lua long string with a RANDOM bracket level.
 *
 * This module is self-contained: it has its own base85 so it does not drag
 * zlib into anything that imports it.
 * ==========================================================================*/

import { xorshift32 } from './ProtoKeygen.js';
import { lzssCompress, emitLzssDecompressorLua } from './lzss.js';
import { ChainKey, deriveChainKey } from './InstrCipher.js';
import { cbMac } from './SilentGuard.js';

/* --------------------------------------------------------------------------
 * base85 (self-contained so this file has no zlib dependency)
 * ------------------------------------------------------------------------*/

export function base85Encode(data: Uint8Array): string {
  let padded = data;
  if (data.length % 4 !== 0) {
    const padLen = 4 - (data.length % 4);
    padded = new Uint8Array(data.length + padLen);
    padded.set(data);
  }
  let result = '';
  for (let i = 0; i < padded.length; i += 4) {
    const uval =
      (((padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3]) >>> 0);
    if (uval === 0) {
      result += 'z';
      continue;
    }
    let v = uval;
    const c = new Array<string>(5);
    for (let j = 4; j >= 0; j--) {
      c[j] = String.fromCharCode(33 + (v % 85));
      v = Math.floor(v / 85);
    }
    result += c.join('');
  }
  return result;
}

/* --------------------------------------------------------------------------
 * The payload cipher: LZSS first, then sbox + CBC-XOR
 * ------------------------------------------------------------------------*/

export interface LayeredPayload {
  blob: string;
  xorKey: number[];
  invSbox: number[];
  checksum: number;
  origLen: number;
  compressedLen: number;
}

function generateSBox(rng: () => number): number[] {
  const sbox = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = sbox[i];
    sbox[i] = sbox[j];
    sbox[j] = t;
  }
  return sbox;
}

function invertSBox(sbox: number[]): number[] {
  const inv = new Array<number>(256);
  for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
  return inv;
}

function adler32(data: Uint8Array): number {
  let a = 1;
  let b = 0;
  const MOD = 65521;
  let idx = 0;
  while (idx < data.length) {
    const end = Math.min(idx + 5552, data.length);
    for (; idx < end; idx++) {
      a += data[idx];
      b += a;
    }
    a %= MOD;
    b %= MOD;
  }
  return (b * 65536 + a) >>> 0;
}

/** LZSS -> sbox substitution -> CBC-XOR -> base85 */
export function buildLayeredPayload(
  source: string,
  rng: () => number
): LayeredPayload {
  const raw = new TextEncoder().encode(source);
  const lz = lzssCompress(raw);

  const sbox = generateSBox(rng);
  const invSbox = invertSBox(sbox);

  const keyLen = 20 + Math.floor(rng() * 13);
  const xorKey: number[] = [];
  for (let i = 0; i < keyLen; i++) xorKey.push(Math.floor(rng() * 256));

  const substituted = new Uint8Array(lz.data.length);
  for (let i = 0; i < lz.data.length; i++) substituted[i] = sbox[lz.data[i]];

  const encrypted = new Uint8Array(substituted.length);
  if (substituted.length > 0) {
    encrypted[0] = substituted[0] ^ xorKey[0];
    for (let i = 1; i < substituted.length; i++) {
      encrypted[i] = substituted[i] ^ xorKey[i % keyLen] ^ encrypted[i - 1];
    }
  }

  return {
    blob: base85Encode(encrypted),
    xorKey,
    invSbox,
    checksum: adler32(raw),
    origLen: raw.length,
    compressedLen: lz.data.length,
  };
}

/* ==========================================================================
 * FRAGMENT GRAPH
 * ========================================================================*/

export const L_BUILTIN = 0;
export const L_JUNK = 1;
export const L_DATA = 2;
export const L_MERGE = 3;
export const L_FUNCS = 4;
export const L_OPAQUE = 5;
export const L_VM = 6;

export interface Fragment {
  code: string;
  layer: number;
  /** names this fragment declares (locals / functions) */
  provides: string[];
  /** names this fragment must see already declared */
  reads: string[];
  tag: string;
}

export interface OrderedFragments {
  order: Fragment[];
  provided: Set<string>;
}

/**
 * Randomised topological sort.
 * Among the fragments whose dependencies are satisfied we always pick one
 * from the LOWEST available layer, and randomly inside that layer.  That
 * keeps the graph valid while making the textual order unpredictable.
 */
export function orderFragments(frags: Fragment[], rng: () => number): OrderedFragments {
  const remaining = frags.slice();
  const provided = new Set<string>();
  const order: Fragment[] = [];

  let guard = frags.length * frags.length + 16;
  while (remaining.length > 0 && guard-- > 0) {
    const ready = remaining.filter(
      (f) => f.reads.every((r) => provided.has(r)) || f.reads.length === 0
    );
    const pool = ready.length > 0 ? ready : remaining;
    const minLayer = Math.min(...pool.map((f) => f.layer));
    const candidates = pool.filter((f) => f.layer === minLayer);
    const pick = candidates[Math.floor(rng() * candidates.length) % candidates.length];

    order.push(pick);
    for (const p of pick.provides) provided.add(p);
    const idx = remaining.indexOf(pick);
    if (idx >= 0) remaining.splice(idx, 1);
  }

  if (remaining.length > 0) {
    // cyclic / unresolvable: append rather than lose code
    for (const f of remaining) order.push(f);
  }

  return { order, provided };
}

/* ==========================================================================
 * JUNK + ANTI-SIMPLIFICATION EMITTERS
 * ========================================================================*/

export function emitJunkFragment(
  nm: (hint: string) => string,
  rng: () => number,
  feeds: string[]
): Fragment {
  const out = nm('jk');
  const a = nm('ja');
  const b = nm('jb');
  const kind = Math.floor(rng() * 3);
  const lines: string[] = [];

  if (kind === 0) {
    lines.push(`local ${a}=${Math.floor(rng() * 977)}`);
    lines.push(`local ${b}=${Math.floor(rng() * 31) + 1}`);
    lines.push(`local ${out}=(${a}*${b}+${Math.floor(rng() * 4096)})%65521`);
  } else if (kind === 1) {
    const s = feeds.length > 0 ? feeds[0] : '"xanax"';
    lines.push(`local ${a}=#${s}`);
    lines.push(`local ${b}=string.byte(${s},${1 + Math.floor(rng() * 3)}) or ${a}`);
    lines.push(`local ${out}=(${a}+${b})*${Math.floor(rng() * 7) + 1}`);
  } else {
    const s = feeds.length > 1 ? feeds[1] : feeds.length > 0 ? feeds[0] : '"vm"';
    lines.push(`local ${a}=#${s}`);
    lines.push(`local ${b}=${a}%${Math.floor(rng() * 13) + 2}`);
    lines.push(`local ${out}=${a}-${b}*${Math.floor(rng() * 5) + 1}`);
  }

  return {
    code: lines.join('\n'),
    layer: L_JUNK,
    provides: [out],
    reads: [],
    tag: 'junk',
  };
}

/** x=y followed by x=x+0 - a simplifier cannot know y is not read later. */
export function emitRedundantAssign(nm: (hint: string) => string, target: string): string {
  const t = nm('ra');
  return `local ${t}=${target}\n${target}=${t}+0`;
}

/** An if-true block whose condition is a provable but non-foldable identity. */
export function emitIfTrueBlock(nm: (hint: string) => string, body: string, v: string): string {
  const x = nm('it');
  return [`local ${x}=${v}`, `if (${x}*${x}+${x})%2==0 then`, body, `end`].join('\n');
}

/** n expressed through an algebraic identity. */
export function emitAlgebraicIdentity(n: number, rng: () => number): string {
  const variant = Math.floor(rng() * 5);
  switch (variant) {
    case 0: {
      const a = Math.floor(rng() * (Math.abs(n) + 1));
      return `(${a}+${n - a})`;
    }
    case 1: {
      const b = 1 + Math.floor(rng() * 300);
      return `(${n + b}-${b})`;
    }
    case 2: {
      const a = 2 + Math.floor(rng() * 11);
      const c = ((n % a) + a) % a;
      const b = (n - c) / a;
      return `(${a}*${b}+${c})`;
    }
    case 3: {
      const k = 1 + Math.floor(rng() * 6);
      return `(${n * k})/${k}`;
    }
    default: {
      const m = 1 + Math.floor(rng() * 7);
      return `(${n + m * 0}-${m * 0})+${n === 0 ? 0 : 0}`;
    }
  }
}

/** Pick a long-string bracket level >= the minimum required for `s`. */
export function longStringLevel(s: string, rng: () => number, minLevel = 0): number {
  let level = minLevel;
  while (s.includes(']' + '='.repeat(level) + ']')) level++;
  // randomise upward so two builds never agree on the delimiter
  return level + (rng() < 0.5 ? 0 : 1 + Math.floor(rng() * 2));
}

/* ==========================================================================
 * THE GENERATOR
 * ========================================================================*/

export interface FragmentedBootstrapConfig {
  /** Full Real-VM + deserialization assembly (already emitted Luau source). */
  vmSource: string;
  chunkName?: string;
  rng: () => number;
  /** seed for the instruction rolling chain (STEP 3) */
  chainSeed: number;
  /** number of junk fragments (3-4 recommended) */
  junkCount?: number;
  /** fragment count target: 8..12 */
  targetFragments?: number;
}

export interface FragmentedBootstrapResult {
  code: string;
  payload: LayeredPayload;
  mac: [number, number];
  chainKey: ChainKey;
  fragmentOrder: string[];
}

/**
 * Build the new bootstrap.  Replaces generateBootstrap() in
 * bootstrap-template.ts.  The returned `code` is a complete, self-executing
 * Luau chunk.
 */
export function generateFragmentedBootstrap(
  cfg: FragmentedBootstrapConfig
): FragmentedBootstrapResult {
  const rng = cfg.rng;
  const nmFactory = () => {
    let n = 0;
    const used = new Set<string>();
    return (hint: string) => {
      let name = `_${hint}${n++}`;
      while (used.has(name)) name = `_${hint}${n++}`;
      used.add(name);
      return name;
    };
  };
  const nm = nmFactory();

  const payload = buildLayeredPayload(cfg.vmSource, rng);
  const chainKey = deriveChainKey(cfg.chainSeed);
  const mac = cbMac(Array.from(new TextEncoder().encode(cfg.vmSource)).slice(0, 32));

  const frags: Fragment[] = [];

  /* ---- 1. builtins, split across fragments ---------------------------- */
  const builtins: [string, string][] = [
    ['byte', 'string.byte'],
    ['char', 'string.char'],
    ['sub', 'string.sub'],
    ['gsub', 'string.gsub'],
    ['tconcat', 'table.concat'],
    ['tinsert', 'table.insert'],
    ['bxor', 'bit32.bxor'],
    ['band', 'bit32.band'],
    ['bor', 'bit32.bor'],
    ['lshift', 'bit32.lshift'],
    ['rshift', 'bit32.rshift'],
    ['load', 'loadstring or load'],
    ['pcall', 'pcall'],
    ['type', 'type'],
    ['assert', 'assert'],
  ];
  const groups = 3 + Math.floor(rng() * 2);
  const perGroup = Math.ceil(builtins.length / groups);
  const builtinNames: Record<string, string> = {};
  for (let g = 0; g < groups; g++) {
    const slice = builtins.slice(g * perGroup, (g + 1) * perGroup);
    if (slice.length === 0) continue;
    const names = slice.map(([k]) => {
      const n = nm(k);
      builtinNames[k] = n;
      return n;
    });
    const values = slice.map(([, v]) => v).join(',');
    frags.push({
      code: `local ${names.join(',')}=${values}`,
      layer: L_BUILTIN,
      provides: names,
      reads: [],
      tag: `builtins-${g}`,
    });
  }

  /* ---- 2. junk fragments (3-4) ---------------------------------------- */
  const junkFeeds: string[] = [];
  const junkCount = cfg.junkCount ?? 3 + Math.floor(rng() * 2);
  for (let i = 0; i < junkCount; i++) {
    const f = emitJunkFragment(nm, rng, ['"' + 'xanax' + '"']);
    junkFeeds.push(f.provides[0]);
    frags.push(f);
  }

  /* ---- 3. key + sbox, each split across fragments --------------------- */
  const keyMask = 1 + Math.floor(rng() * 254);
  const sboxMask = 1 + Math.floor(rng() * 254);
  const maskedKey = payload.xorKey.map((b) => b ^ keyMask);
  const maskedSbox = payload.invSbox.map((b) => b ^ sboxMask);

  const splitArray = (data: number[], baseName: string, tag: string) => {
    const numFrags = 3 + Math.floor(rng() * 3);
    const fragNames: string[] = [];
    const sizes: number[] = [];
    let remaining = data.length;
    for (let i = 0; i < numFrags; i++) {
      const left = numFrags - i;
      const take = i === numFrags - 1 ? remaining : Math.floor(remaining / left);
      sizes.push(take);
      remaining -= take;
    }
    let offset = 0;
    for (let i = 0; i < numFrags; i++) {
      if (sizes[i] <= 0) continue;
      const pn = nm(tag);
      fragNames.push(pn);
      const chunk = data.slice(offset, offset + sizes[i]).map((b) => b & 0xff);
      frags.push({
        code: `local ${pn}={${chunk.join(',')}}`,
        layer: L_DATA,
        provides: [pn],
        reads: [],
        tag: `${tag}-data-${i}`,
      });
      offset += sizes[i];
    }
    const counter = nm('ctr');
    const mergeLines = [`local ${baseName}={}`, `local ${counter}=0`];
    for (const fn of fragNames) {
      mergeLines.push(`for _0i=1,#${fn} do ${counter}=${counter}+1 ${baseName}[${counter}]=${fn}[_0i] end`);
    }
    frags.push({
      code: mergeLines.join('\n'),
      layer: L_MERGE,
      provides: [baseName],
      reads: fragNames,
      tag: `${tag}-merge`,
    });
    return baseName;
  };

  const nKeyRaw = nm('keyraw');
  const nKey = nm('key');
  const nSboxRaw = nm('sboxraw');
  const nSbox = nm('sbox');
  const nKeyLen = nm('keylen');

  splitArray(maskedSbox, nSboxRaw, 'sb');
  splitArray(maskedKey, nKeyRaw, 'kb');

  frags.push({
    code: [
      `local ${nKey}={}`,
      `for _0i=1,#${nKeyRaw} do ${nKey}[_0i]=bit32.bxor(${nKeyRaw}[_0i],${keyMask}) end`,
      `local ${nKeyLen}=#${nKey}`,
      `local ${nSbox}={}`,
      `for _0i=1,#${nSboxRaw} do ${nSbox}[_0i]=bit32.bxor(${nSboxRaw}[_0i],${sboxMask}) end`,
      emitRedundantAssign(nm, nKeyLen),
    ].join('\n'),
    layer: L_MERGE,
    provides: [nKey, nKeyLen, nSbox],
    reads: [nKeyRaw, nSboxRaw],
    tag: 'unmask',
  });

  /* ---- 4. LZSS inflate (STEP 10.5) ------------------------------------ */
  /* The payload pipeline is:
   *     LZSS compress -> sbox/CBC-XOR -> base85 -> long string
   * so at runtime it unwinds as:
   *     base85 decode -> cipher decrypt -> LZSS inflate -> Real VM source
   * The compressed bytes never appear as a literal anywhere.
   */
  const inflate = emitLzssDecompressorLua({
    nm,
    nByte: builtinNames['byte'],
    nChar: builtinNames['char'],
    nTconcat: builtinNames['tconcat'],
    nBand: builtinNames['band'],
    nRshift: builtinNames['rshift'],
    nPayload: 's',
  });
  const nInflate = inflate.name;
  frags.push({
    code: inflate.code,
    layer: L_FUNCS,
    provides: [nInflate],
    reads: [
      builtinNames['byte'],
      builtinNames['char'],
      builtinNames['tconcat'],
      builtinNames['band'],
      builtinNames['rshift'],
    ],
    tag: 'lzss-inflate',
  });

  /* ---- 5. base85 decoder ---------------------------------------------- */
  const nDecode = nm('b85');
  frags.push({
    code: [
      `local function ${nDecode}(s)`,
      ` s=s:gsub("z","!!!!!")`,
      ` local o={}`,
      ` local i=1`,
      ` while i<=#s do`,
      `  local v=0`,
      `  for j=0,4 do v=v*85+(s:byte(i+j)-33) end`,
      `  o[#o+1]=string.char(math.floor(v/16777216)%256)`,
      `  o[#o+1]=string.char(math.floor(v/65536)%256)`,
      `  o[#o+1]=string.char(math.floor(v/256)%256)`,
      `  o[#o+1]=string.char(v%256)`,
      `  i=i+5`,
      ` end`,
      ` return table.concat(o)`,
      `end`,
    ].join('\n'),
    layer: L_FUNCS,
    provides: [nDecode],
    reads: [],
    tag: 'base85',
  });

  /* ---- 6. cipher decrypt (inverse of buildLayeredPayload) ------------- */
  const nDecrypt = nm('dec');
  frags.push({
    code: [
      `local function ${nDecrypt}(s)`,
      ` local o={}`,
      ` local prev=0`,
      ` for i=1,#s do`,
      `  local e=${builtinNames['byte']}(s,i)`,
      `  local x=${builtinNames['bxor']}(${builtinNames['bxor']}(e,${nKey}[((i-1)%${nKeyLen})+1]),prev)`,
      `  o[i]=${builtinNames['char']}(${nSbox}[x+1])`,
      `  prev=e`,
      ` end`,
      ` return ${builtinNames['tconcat']}(o)`,
      `end`,
    ].join('\n'),
    layer: L_FUNCS,
    provides: [nDecrypt],
    reads: [nKey, nKeyLen, nSbox, builtinNames['byte'], builtinNames['char'], builtinNames['bxor'], builtinNames['tconcat']],
    tag: 'decrypt',
  });

  /* ---- 7. verify ------------------------------------------------------ */
  const nVerify = nm('verify');
  frags.push({
    code: [
      `local function ${nVerify}(s)`,
      ` local a,b=1,0`,
      ` for i=1,#s do`,
      `  a=(a+${builtinNames['byte']}(s,i))%65521`,
      `  b=(b+a)%65521`,
      ` end`,
      ` return b*65536+a`,
      `end`,
    ].join('\n'),
    layer: L_FUNCS,
    provides: [nVerify],
    reads: [builtinNames['byte']],
    tag: 'verify',
  });

  /* ---- 8. opaque predicate feeding junk vars -------------------------- */
  const nOpaA = nm('opa');
  const nOpaB = nm('opb');
  frags.push({
    code: [
      `local ${nOpaA}=${junkFeeds[0] ?? 1}`,
      `local ${nOpaB}=${junkFeeds[1] ?? 1}`,
      `if (${nOpaA}*${nOpaA}+${nOpaA})%2~=0 then ${nOpaB}=${nOpaB}+1 end`,
    ].join('\n'),
    layer: L_OPAQUE,
    provides: [nOpaA, nOpaB],
    reads: junkFeeds.slice(0, 2),
    tag: 'opaque',
  });

  /* ---- 9. blob as a long string with a random bracket level ---------- */
  const lvl = longStringLevel(payload.blob, rng);
  const open = '[' + '='.repeat(lvl) + '[';
  const close = ']' + '='.repeat(lvl) + ']';
  const nBlob = nm('blob');
  frags.push({
    code: `local ${nBlob}=${open}${payload.blob}${close}`,
    layer: L_DATA,
    provides: [nBlob],
    reads: [],
    tag: 'blob',
  });

  /* ---- 10. assemble --------------------------------------------------- */
  const ordered = orderFragments(frags, rng);

  const out: string[] = [];
  out.push('-- Xanax Protection v15 (fragmented bootstrap, STEP 10)');
  out.push('return (function(...)');
  for (const f of ordered.order) {
    out.push(f.code);
  }

  const nRaw = nm('raw');
  const nCmp = nm('cmp');
  const nPlain = nm('plain');
  const nOk = nm('ok');
  const nFn = nm('fn');
  const nResult = nm('result');

  out.push(`local ${nRaw},${nCmp},${nPlain},${nOk},${nFn},${nResult}`);
  out.push(`-- base85 -> cipher -> LZSS inflate`);
  out.push(`${nRaw}=${nDecode}(${nBlob})`);
  out.push(`${nCmp}=${nDecrypt}(${nRaw})`);
  out.push(`${nPlain}=${nInflate}(${nCmp})`);
  out.push(
    emitSilentLoad({
      nVerify,
      nPlain,
      nOk,
      nFn,
      nLoad: builtinNames['load'],
      nPcall: builtinNames['pcall'],
      nAssert: builtinNames['assert'],
      nResult,
      checksum: payload.checksum,
      origLen: payload.origLen,
      chunkName: cfg.chunkName ?? '=[xanax]',
      junk: junkFeeds,
    })
  );
  out.push(
    [
      `-- STEP 4.5: key material, round keys and the code table are dead now`,
      `for _0i=1,#${nKey} do ${nKey}[_0i]=0 end`,
      `for _0i=1,#${nSbox} do ${nSbox}[_0i]=0 end`,
      `for _0i=1,#${nKeyRaw} do ${nKeyRaw}[_0i]=0 end`,
      `for _0i=1,#${nSboxRaw} do ${nSboxRaw}[_0i]=0 end`,
      `${nBlob}=nil`,
      `${nRaw}=nil`,
      `${nCmp}=nil`,
      `${nPlain}=nil`,
      `_G.collectgarbage and collectgarbage("step")`,
    ].join('\n')
  );
  out.push(`return ${nResult}`);
  out.push('end)(...)');

  return {
    code: out.join('\n'),
    payload,
    mac,
    chainKey,
    fragmentOrder: ordered.order.map((f) => f.tag),
  };
}

/**
 * The load step - SILENT (STEP 4).  A checksum mismatch never raises: it
 * poisons the source string instead, so `load` either fails quietly or
 * produces a function that does nothing useful.  There is no oracle.
 */
function emitSilentLoad(o: {
  nVerify: string;
  nPlain: string;
  nOk: string;
  nFn: string;
  nLoad: string;
  nPcall: string;
  nAssert: string;
  nResult: string;
  checksum: number;
  origLen: number;
  chunkName: string;
  junk: string[];
}): string {
  const lines: string[] = [];
  lines.push(`-- silent integrity fold (STEP 4): no comparison branch, no oracle`);
  lines.push(`local _a1=${o.nVerify}(${o.nPlain})`);
  lines.push(`-- _d is 0 exactly when the checksum matches, so _m is 1 on a`);
  lines.push(`-- match and 0 otherwise.  No and/or, no if, nothing to hook.`);
  lines.push(`local _d=(_a1-${o.checksum >>> 0})*(_a1-${o.checksum >>> 0})`);
  lines.push(`local _m=1//(1+_d)`);
  lines.push(`-- truncating to _m * len keeps the whole source on a match and`);
  lines.push(`-- yields the empty string otherwise.  load("") still succeeds, so`);
  lines.push(`-- a tampered build quietly runs a no-op instead of raising.`);
  lines.push(`local _src=${o.nPlain}:sub(1,_m*#${o.nPlain})`);
  lines.push(`${o.nOk},${o.nFn}=${o.nPcall}(${o.nLoad},_src,${JSON.stringify(o.chunkName)})`);
  lines.push(`${o.nResult}=(${o.nOk} and ${o.nFn}) and ${o.nFn}(...) or nil`);
  return lines.join('\n');
}

/** Deterministic convenience wrapper used by the CLI / check script. */
export function generateWithSeed(
  vmSource: string,
  seed: number,
  chainSeed = seed ^ 0x5f3759df
): FragmentedBootstrapResult {
  return generateFragmentedBootstrap({
    vmSource,
    rng: xorshift32(seed),
    chainSeed,
  });
}
