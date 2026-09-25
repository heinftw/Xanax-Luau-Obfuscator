/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/InstrCipher.ts
 * PART 1 / STEP 3 : MULTI-LAYER INSTRUCTION ENCRYPTION
 * PART 1 / STEP 9 : PER-ARGUMENT ENCRYPTION
 * ----------------------------------------------------------------------------
 * Stock behaviour: serializeRegCode() encrypts only the opcode field; A/B/C
 * travel in plaintext, so a dump of the code table plus the decode table is
 * enough to read every operand.
 *
 * New behaviour - three independent layers over every instruction word:
 *
 *   L1  opcode  : XOR  cipher, key derived from (ip, chain)
 *   L2  A/B/C   : ADD/SUB cipher, key derived from (DECRYPTED opcode,
 *                 argument position, ip, chain)   <-- STEP 9
 *   L3  layout  : the ar() pipeline rotates the whole 4-tuple by
 *                 (ip + mix) % 4 so fields are not even in fixed slots
 *
 *   rolling chain (STEP 3, verbatim):
 *     chain = ((chain ^ eOp ^ eA ^ eB ^ eC) * chainMul + chainStep + mix) & 0xFF
 *
 *   constants  : encrypted with a SEPARATE cipher/derivation (STEP 3.5) and
 *                decrypted during deserialization into decrypted_constants.
 *
 * The encryption side (this file) and the Luau decrypt side
 * (emitDecryptSectionLua) are two halves of one bijection.  If you change a
 * constant here you MUST change it there - real_check-script has a
 * round-trip test (roundTripInstruction) that fails loudly if you forget.
 * ==========================================================================*/

import { RegBytecodeChunk, Constant } from './bytecode.js';

/* --------------------------------------------------------------------------
 * Magic constants (v14.2: "changed magic numbers to break tools")
 * ------------------------------------------------------------------------*/

export const INSTR_MAGIC = {
  OP_MUL: 0x9e,
  OP_ADD: 0x37,
  ARG_MUL: [0x0b, 0x71, 0x1d] as const,
  ARG_ADD: [0x31, 0x5f, 0x17] as const,
  ARG_POS: 0x2b,
  ARG_CHAIN: 0x11,
  CHAIN_MUL: 0xb7,
  CHAIN_STEP: 0x6d,
  CHAIN_MIX: 0x3b,
  CHAIN_SEED_SALT: 0x5c,
  CONST_MUL: 0xa1,
  CONST_STEP: 0x47,
  CONST_SALT: 0xd3,
} as const;

export const FIELD_MASK = 0xffff;

/** Max value a field may carry: RK indices go up to 256 + |K| - 1. */
export const MAX_FIELD = FIELD_MASK;
export const MAX_CONSTS = FIELD_MASK - 256 + 1;

export interface ChainKey {
  seed: number;
  mul: number;
  step: number;
  mix: number;
}

export interface ChainState extends ChainKey {
  chain: number;
}

/** Derive the rolling-key material from a 32-bit seed. */
export function deriveChainKey(seed: number): ChainKey {
  const s = seed >>> 0;
  return {
    seed: s,
    mul: (INSTR_MAGIC.CHAIN_MUL ^ ((s >>> 3) & 0x0f)) & 0xff,
    step: (INSTR_MAGIC.CHAIN_STEP ^ ((s >>> 11) & 0x0f)) & 0xff,
    mix: (INSTR_MAGIC.CHAIN_MIX ^ ((s >>> 19) & 0x0f)) & 0xff,
  };
}

export function initChainState(key: ChainKey): ChainState {
  return {
    ...key,
    chain: (key.seed ^ INSTR_MAGIC.CHAIN_SEED_SALT) & 0xff,
  };
}

const mod = (n: number, m: number) => ((n % m) + m) % m;

/* --------------------------------------------------------------------------
 * L1 - opcode (XOR)
 * ------------------------------------------------------------------------*/

export function opKeyOf(ip: number, chain: number): number {
  return (ip * INSTR_MAGIC.OP_MUL + INSTR_MAGIC.OP_ADD + chain) & 0xff;
}

/* --------------------------------------------------------------------------
 * L2 - arguments (ADD/SUB).  Key depends on the DECRYPTED opcode, so an
 *      attacker cannot recover an operand without first recovering the
 *      opcode - which requires the rolling chain, which requires executing
 *      every earlier instruction in order.
 * ------------------------------------------------------------------------*/

export type ArgPos = 0 | 1 | 2;

export function argKeyOf(op: number, pos: ArgPos, ip: number, chain: number): number {
  return (
    (op * INSTR_MAGIC.ARG_MUL[pos] +
      ip * INSTR_MAGIC.ARG_ADD[pos] +
      (pos + 1) * INSTR_MAGIC.ARG_POS +
      chain * INSTR_MAGIC.ARG_CHAIN) &
    FIELD_MASK
  );
}

/* --------------------------------------------------------------------------
 * L3 - ar() layout pipeline: rotate all four fields together
 * ------------------------------------------------------------------------*/

export type Quad = [number, number, number, number];

export function arRotate(q: Quad, ip: number, mix: number): Quad {
  const k = mod(ip + mix, 4);
  return [q[k], q[(k + 1) % 4], q[(k + 2) % 4], q[(k + 3) % 4]];
}

export function arInverse(q: Quad, ip: number, mix: number): Quad {
  const k = mod(ip + mix, 4);
  const out: Quad = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) out[(k + i) % 4] = q[i];
  return out;
}

/* --------------------------------------------------------------------------
 * The bijection
 * ------------------------------------------------------------------------*/

export interface EncodedInstruction {
  w: Quad;
  chain: number;
}

/**
 * Encrypt one instruction.
 *   ip     - 0-based instruction index
 *   op/A/B/C - WIRE values (already per-proto mapped + deviated)
 */
export function encryptInstruction(
  st: ChainState,
  ip: number,
  op: number,
  A: number,
  B: number,
  C: number
): EncodedInstruction {
  if (A > MAX_FIELD || B > MAX_FIELD || C > MAX_FIELD) {
    throw new Error(
      `Xanax/InstrCipher: field overflow (A=${A},B=${B},C=${C}) - too many constants`
    );
  }
  const chain = st.chain;

  const eOp = (op ^ opKeyOf(ip, chain)) & 0xff;
  const kA = argKeyOf(op, 0, ip, chain);
  const kB = argKeyOf(op, 1, ip, chain);
  const kC = argKeyOf(op, 2, ip, chain);

  const eA = (A + kA) & FIELD_MASK;
  const eB = (B + kB) & FIELD_MASK;
  const eC = (C + kC) & FIELD_MASK;

  // STEP 3 rolling chain - verbatim
  st.chain =
    (((chain ^ eOp ^ eA ^ eB ^ eC) * st.mul + st.step + st.mix) & 0xff) >>> 0;

  const w = arRotate([eOp, eA, eB, eC], ip, st.mix);
  return { w, chain };
}

/** Inverse of encryptInstruction.  `st` is advanced identically. */
export function decryptInstruction(
  st: ChainState,
  ip: number,
  w0: number,
  w1: number,
  w2: number,
  w3: number
): { op: number; A: number; B: number; C: number } {
  const [eOp, eA, eB, eC] = arInverse([w0, w1, w2, w3], ip, st.mix);
  const chain = st.chain;

  const op = (eOp ^ opKeyOf(ip, chain)) & 0xff;
  const A = mod(eA - argKeyOf(op, 0, ip, chain), FIELD_MASK + 1);
  const B = mod(eB - argKeyOf(op, 1, ip, chain), FIELD_MASK + 1);
  const C = mod(eC - argKeyOf(op, 2, ip, chain), FIELD_MASK + 1);

  st.chain =
    (((chain ^ eOp ^ eA ^ eB ^ eC) * st.mul + st.step + st.mix) & 0xff) >>> 0;

  return { op, A, B, C };
}

/** Round-trip self check.  Call this from real_check-script. */
export function roundTripInstruction(seed: number, samples = 512): boolean {
  const key = deriveChainKey(seed);
  const st = initChainState(key);
  const st2 = initChainState(key);
  for (let ip = 0; ip < samples; ip++) {
    const op = (ip * 7) & 0x3f;
    const A = (ip * 97) & FIELD_MASK;
    const B = (ip * 131) & FIELD_MASK;
    const C = (ip * 197) & FIELD_MASK;
    const enc = encryptInstruction(st, ip, op, A, B, C);
    const dec = decryptInstruction(st2, ip, enc.w[0], enc.w[1], enc.w[2], enc.w[3]);
    if (dec.op !== op || dec.A !== A || dec.B !== B || dec.C !== C) return false;
    if (st.chain !== st2.chain) return false;
  }
  return true;
}

/* --------------------------------------------------------------------------
 * Whole-proto encryption (drop-in for the body of serializeRegCode)
 * ------------------------------------------------------------------------*/

/**
 * Encrypt a proto's wire code array IN PLACE and return the flat encrypted
 * stream.  Call AFTER per-proto opcode mapping and after applyRegDeviations.
 *
 * Returns the words in the order they must be serialised:
 *   [w0_0,w0_1,w0_2,w0_3, w1_0, ...]
 */
export function encryptRegCode(
  chunk: RegBytecodeChunk,
  key: ChainKey,
  sink: number[] = []
): number[] {
  const st = initChainState(key);
  const code = chunk.code;
  for (let pos = 0; pos + 3 < code.length; pos += 4) {
    const ip = pos / 4;
    const enc = encryptInstruction(st, ip, code[pos], code[pos + 1], code[pos + 2], code[pos + 3]);
    sink.push(enc.w[0], enc.w[1], enc.w[2], enc.w[3]);
  }
  return sink;
}

/** Inverse - used by tooling and by the round-trip check. */
export function decryptRegCode(words: number[], key: ChainKey): number[] {
  const st = initChainState(key);
  const out: number[] = [];
  for (let i = 0; i + 3 < words.length; i += 4) {
    const ip = i / 4;
    const d = decryptInstruction(st, ip, words[i], words[i + 1], words[i + 2], words[i + 3]);
    out.push(d.op, d.A, d.B, d.C);
  }
  return out;
}

/* ==========================================================================
 * STEP 3.5 - CONSTANT TABLE ENCRYPTION (separate cipher / separate derivation)
 * ==========================================================================*/

export const CONST_KIND = { NIL: 0, FALSE: 1, TRUE: 2, NUMBER: 3, STRING: 4 } as const;

/** Serialise one constant to bytes.  Numbers use decimal text so the Luau
 *  side needs no bit-manipulation to rebuild them. */
export function packConstant(value: Constant, out: number[] = []): number[] {
  if (value === null || value === undefined) {
    out.push(CONST_KIND.NIL);
  } else if (value === false) {
    out.push(CONST_KIND.FALSE);
  } else if (value === true) {
    out.push(CONST_KIND.TRUE);
  } else if (typeof value === 'number') {
    out.push(CONST_KIND.NUMBER);
    const s = numberToText(value);
    pushLen(out, s.length);
    for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
  } else {
    out.push(CONST_KIND.STRING);
    pushLen(out, value.length);
    for (let i = 0; i < value.length; i++) out.push(value.charCodeAt(i) & 0xff);
  }
  return out;
}

function pushLen(out: number[], len: number): void {
  out.push(len & 0xff, (len >>> 8) & 0xff);
}

function numberToText(n: number): string {
  if (Number.isInteger(n) && Math.abs(n) < 1e15) return String(n);
  return String(n);
}

export interface EncryptedConstants {
  bytes: number[];
  /** Number of words the rolling cipher is seeded with. */
  seed: number;
  checksum: number;
}

/**
 * Encrypt the whole K table with the CONSTANT cipher (XOR + ADD rolling,
 * different multiplier/step/salt from the instruction cipher).
 */
export function encryptConstantTable(K: Constant[], seed: number): EncryptedConstants {
  const plain: number[] = [];
  for (const k of K) packConstant(k, plain);
  if (plain.length > 0xffff) throw new Error('Xanax/InstrCipher: constant table too large');

  const bytes: number[] = [];
  let c = (seed ^ INSTR_MAGIC.CONST_SALT) & 0xff;
  for (let i = 0; i < plain.length; i++) {
    const e = (plain[i] + ((c * INSTR_MAGIC.CONST_MUL + INSTR_MAGIC.CONST_STEP + i) & 0xff)) & 0xff;
    bytes.push(e);
    c = (e ^ c) & 0xff;
  }

  let checksum = 0x811c9dc5;
  for (const b of bytes) checksum = ((checksum ^ b) * 0x01000193) >>> 0;

  return { bytes, seed: seed >>> 0, checksum: checksum >>> 0 };
}

/** Inverse - used by tooling + the self check. */
export function decryptConstantTable(enc: EncryptedConstants): Constant[] {
  const plain: number[] = [];
  let c = (enc.seed ^ INSTR_MAGIC.CONST_SALT) & 0xff;
  for (let i = 0; i < enc.bytes.length; i++) {
    const e = enc.bytes[i];
    plain.push(mod(e - ((c * INSTR_MAGIC.CONST_MUL + INSTR_MAGIC.CONST_STEP + i) & 0xff), 256));
    c = (e ^ c) & 0xff;
  }

  const out: Constant[] = [];
  let p = 0;
  while (p < plain.length) {
    const kind = plain[p++];
    if (kind === CONST_KIND.NIL) out.push(null);
    else if (kind === CONST_KIND.FALSE) out.push(false);
    else if (kind === CONST_KIND.TRUE) out.push(true);
    else {
      const lo = plain[p++];
      const hi = plain[p++];
      const len = lo | (hi << 8);
      let s = '';
      for (let i = 0; i < len; i++) s += String.fromCharCode(plain[p++]);
      out.push(kind === CONST_KIND.NUMBER ? Number(s) : s);
    }
  }
  return out;
}

/** Round-trip self check for the constant layer. */
export function roundTripConstants(seed: number): boolean {
  const sample: Constant[] = [
    null,
    true,
    false,
    0,
    -1,
    3.25,
    1e9,
    '',
    'hello',
    'with "quotes" and \\backslash',
    '\n\tunicode-ish',
  ];
  const enc = encryptConstantTable(sample, seed);
  const dec = decryptConstantTable(enc);
  if (dec.length !== sample.length) return false;
  for (let i = 0; i < sample.length; i++) {
    const a = sample[i];
    const b = dec[i];
    if (typeof a === 'number') {
      if (typeof b !== 'number' || a !== b) return false;
    } else if (a !== b) return false;
  }
  return true;
}

/* ==========================================================================
 * LUAU EMISSION - the decrypt half of the bijection
 * ==========================================================================*/

export interface DecryptEmitCtx {
  /** local holding the encrypted word stream (1-based Luau table). */
  nWords: string;
  /** locals to write the plaintext fields into (1-based tables). */
  nOp: string;
  nA: string;
  nB: string;
  nC: string;
  /** local holding the number of instructions. */
  nCount: string;
  /** locals for the chain key material. */
  nChain: string;
  nMul: string;
  nStep: string;
  nMix: string;
  /** bit32.band / bit32.bxor names from the bootstrap. */
  nBand: string;
  nBxor: string;
  /** name generator for temporaries. */
  nm: (hint: string) => string;
}

/**
 * Emits the dispatch-side decrypt loop.  It decrypts ALL FOUR fields before
 * dispatch (STEP 3) and derives the argument keys from the freshly decrypted
 * opcode (STEP 9).
 *
 * Drop this into buildVMRuntime()'s decrypt section, replacing the loop that
 * only un-XORed the opcode.
 */
export function emitDecryptSectionLua(ctx: DecryptEmitCtx): string {
  const { nWords, nOp, nA, nB, nC, nCount, nChain, nMul, nStep, nMix, nBand, nBxor, nm } = ctx;
  const i = nm('di');
  const w0 = nm('w0');
  const w1 = nm('w1');
  const w2 = nm('w2');
  const w3 = nm('w3');
  const eOp = nm('eo');
  const eA = nm('ea');
  const eB = nm('eb');
  const eC = nm('ec');
  const t = nm('t');
  const q = nm('q');

  return [
    `-- multi-layer instruction decryption (STEP 3 + STEP 9)`,
    `local ${i}=1`,
    `while ${i}<=${nCount} do`,
    ` local ${w0}=${nWords}[(${i}-1)*4+1]`,
    ` local ${w1}=${nWords}[(${i}-1)*4+2]`,
    ` local ${w2}=${nWords}[(${i}-1)*4+3]`,
    ` local ${w3}=${nWords}[(${i}-1)*4+4]`,
    ` -- L3: ar() inverse - undo the whole-tuple rotation`,
    ` -- arRotate stored w[j] = plain[(q+j)%4], so plain[m] = w[(m-q)%4]`,
    ` local ${q}=(${i}-1+${nMix})%4`,
    ` local ${t}={${w0},${w1},${w2},${w3}}`,
    ` local ${eOp}=${t}[(4-${q})%4+1]`,
    ` local ${eA}=${t}[(5-${q})%4+1]`,
    ` local ${eB}=${t}[(6-${q})%4+1]`,
    ` local ${eC}=${t}[(7-${q})%4+1]`,
    ` -- L1: opcode (XOR)`,
    ` local _op=${nBxor}(${eOp},(${i}-1)*${INSTR_MAGIC.OP_MUL}+${INSTR_MAGIC.OP_ADD}+${nChain})%256`,
    ` -- L2: operands (ADD/SUB), keyed by the DECRYPTED opcode`,
    ` local _A=(${eA}-(_op*${INSTR_MAGIC.ARG_MUL[0]}+(${i}-1)*${INSTR_MAGIC.ARG_ADD[0]}+${INSTR_MAGIC.ARG_POS}+${nChain}*${INSTR_MAGIC.ARG_CHAIN}))%65536`,
    ` local _B=(${eB}-(_op*${INSTR_MAGIC.ARG_MUL[1]}+(${i}-1)*${INSTR_MAGIC.ARG_ADD[1]}+2*${INSTR_MAGIC.ARG_POS}+${nChain}*${INSTR_MAGIC.ARG_CHAIN}))%65536`,
    ` local _C=(${eC}-(_op*${INSTR_MAGIC.ARG_MUL[2]}+(${i}-1)*${INSTR_MAGIC.ARG_ADD[2]}+3*${INSTR_MAGIC.ARG_POS}+${nChain}*${INSTR_MAGIC.ARG_CHAIN}))%65536`,
    ` ${nOp}[${i}]=_op`,
    ` ${nA}[${i}]=_A`,
    ` ${nB}[${i}]=_B`,
    ` ${nC}[${i}]=_C`,
    ` -- rolling chain, verbatim`,
    ` ${nChain}=${nBand}(${nBxor}(${nBxor}(${nBxor}(${nBxor}(${nChain},${eOp}),${eA}),${eB}),${eC})*${nMul}+${nStep}+${nMix},255)`,
    ` ${i}=${i}+1`,
    `end`,
  ].join('\n');
}

/**
 * Emits the constant-table decryptor.  Produces `decrypted_constants` from
 * the encrypted byte stream held in `constants`.
 */
export function emitConstantDecryptLua(
  nm: (hint: string) => string,
  nDecrypted: string,
  nChar: string,
  nTconcat: string,
  nBxor: string,
  seed: number
): string {
  const i = nm('ci');
  const p = nm('cp');
  const n = nm('cn');
  const c = nm('cc');
  const e = nm('ce');
  const kind = nm('ck');
  const len = nm('cl');
  const buf = nm('cb');
  const tmp = nm('ct');
  const s = nm('cs');

  return [
    `-- constant decryption (STEP 3.5) - separate cipher from instructions`,
    `local function ${nDecrypted}(src)`,
    ` local ${n}=#src`,
    ` local ${c}=${(seed ^ INSTR_MAGIC.CONST_SALT) & 0xff}`,
    ` local ${buf}={}`,
    ` local ${p}=1`,
    ` while ${p}<=${n} do`,
    `  local ${e}=src[${p}]`,
    `  ${buf}[#${buf}+1]=(${e}-(${c}*${INSTR_MAGIC.CONST_MUL}+${INSTR_MAGIC.CONST_STEP}+${p}-1))%256`,
    `  ${c}=${nBxor}(${e},${c})`,
    `  ${p}=${p}+1`,
    ` end`,
    ` -- rebuild typed values`,
    ` local out={}`,
    ` local ${i}=1`,
    ` while ${i}<=#${buf} do`,
    `  local ${kind}=${buf}[${i}]`,
    `  if ${kind}==0 then out[#out+1]=nil`,
    `  elseif ${kind}==1 then out[#out+1]=false`,
    `  elseif ${kind}==2 then out[#out+1]=true`,
    `  else`,
    `   local ${len}=${buf}[${i}+1]+${buf}[${i}+2]*256`,
    `   local ${tmp}={}`,
    `   for _0k=1,${len} do ${tmp}[_0k]=${nChar}(${buf}[${i}+2+_0k]) end`,
    `   local ${s}=${nTconcat}(${tmp})`,
    `   out[#out+1]=(${kind}==3) and tonumber(${s}) or ${s}`,
    `   ${i}=${i}+2+${len}`,
    `  end`,
    `  ${i}=${i}+1`,
    ` end`,
    ` return out`,
    `end`,
  ].join('\n');
}
