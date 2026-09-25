/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/DeserCompiler.ts
 * PART 1 / STEP 2 : DESERIALIZATION VM LAYER
 * ----------------------------------------------------------------------------
 * Luraph v15 is a two-stage, single-VM-at-a-time architecture (birk.blog):
 *
 *   Stage 1 "Deserialization VM" (~20k instructions)
 *     - reconstructs the instruction stream, constants and prototypes from
 *       the encrypted blob
 *     - has its OWN instruction set (~9-20 opcodes) and its OWN shuffled
 *       opcode table, completely unrelated to the Real VM's
 *     - enforces anti-tamper while reconstructing
 *     - output table:
 *         constants, decrypted_constants, Insts, REG_A, REG_B, REG_C,
 *         prototypes, upvalues, entrypoint
 *
 *   Stage 2 "Real VM" (~5k instructions)
 *     - consumes the deserialized data and executes
 *
 * Handoff is clean: only ONE VM is live at any moment, there is no nesting.
 * After the handoff the deserialization interpreter and its data are dropped
 * so they become garbage collectable.
 *
 * PIPELINE
 *   base85 -> LZSS decompress -> Speck32/whitening decrypt
 *          -> DESERIALIZATION VM (this file)
 *          -> Real VM (reg-vm-gen.ts buildVMRuntime)
 *
 * The Speck32-decrypted blob is now DESERIALIZATION DATA, not Real VM code.
 * ==========================================================================*/

import { RegBytecodeChunk } from './bytecode.js';
import { xorshift32 } from './ProtoKeygen.js';

/* --------------------------------------------------------------------------
 * The deserialization instruction set
 * ------------------------------------------------------------------------*/

export const enum DeserOp {
  LOAD_BYTE = 0, // M[a]        = b
  XOR_RANGE = 1, // M[a+i]      = bxor(M[a+i], b)          for i in [0,c)
  SWAP_RANGE = 2, // M[a+i],M[b+i] = M[b+i],M[a+i]         for i in [0,c)
  COPY_BLOCK = 3, // OUTARR[a][i+1] = M[b+i]               for i in [0,c)
  WRITE_FIELD = 4, // OUTSCALAR[a]  = M[b]
  TRANSFORM_TABLE = 5, // M[a+i] = (M[a+i] * b + c) % 65536
  JMP = 6, // pc = a
  JMP_IF_ZERO = 7, // if M[a] == 0 then pc = b end
  HALT = 8, // stop
}

export const DESER_OPCODE_COUNT = 9;

/** Field ids used by WRITE_FIELD / COPY_BLOCK. */
export const DESER_FIELD = {
  INSTS: 0,
  REG_A: 1,
  REG_B: 2,
  REG_C: 3,
  CONSTANTS: 4,
  DECRYPTED_CONSTANTS: 5,
  PROTOTYPES: 6,
  UPVALUES: 7,
  ENTRYPOINT: 8,
  NINSTR: 9,
  MAXREGS: 10,
  NPARAMS: 11,
  VARARG: 12,
  MAC_LO: 13,
  MAC_HI: 14,
} as const;

/** Scalar output fields (addressable by WRITE_FIELD). */
export const DESER_SCALAR_FIELDS: number[] = [
  DESER_FIELD.ENTRYPOINT,
  DESER_FIELD.NINSTR,
  DESER_FIELD.MAXREGS,
  DESER_FIELD.NPARAMS,
  DESER_FIELD.VARARG,
  DESER_FIELD.MAC_LO,
  DESER_FIELD.MAC_HI,
];

/** Array output fields (addressable by COPY_BLOCK). */
export const DESER_ARRAY_FIELDS: number[] = [
  DESER_FIELD.INSTS,
  DESER_FIELD.REG_A,
  DESER_FIELD.REG_B,
  DESER_FIELD.REG_C,
  DESER_FIELD.CONSTANTS,
  DESER_FIELD.PROTOTYPES,
  DESER_FIELD.UPVALUES,
];

export const DESER_MEM_LIMIT = 1 << 16;

/* --------------------------------------------------------------------------
 * Transform layers
 * ------------------------------------------------------------------------*/

export type DeserLayer =
  | { kind: 'xor'; base: number; key: number; len: number }
  | { kind: 'transform'; base: number; mul: number; add: number; len: number }
  | { kind: 'swap'; a: number; b: number; len: number };

const M16 = 0x10000;
const mod = (n: number, m: number) => ((n % m) + m) % m;

/** Modular inverse of an odd multiplier modulo 2^16 (extended Euclid). */
export function modInverse16(m: number): number {
  let a = M16;
  let b = mod(m, M16) | 1;
  let x0 = 0;
  let x1 = 1;
  while (b !== 0) {
    const q = Math.floor(a / b);
    const t = a - q * b;
    a = b;
    b = t;
    const tx = x0 - q * x1;
    x0 = x1;
    x1 = tx;
  }
  if (a !== 1) throw new Error('Xanax/DeserCompiler: multiplier not invertible mod 2^16');
  return mod(x0, M16);
}

function applyLayerForward(M: number[], l: DeserLayer): void {
  switch (l.kind) {
    case 'xor':
      for (let i = 0; i < l.len; i++) M[l.base + i] = (M[l.base + i] ^ l.key) & 0xff;
      break;
    case 'transform':
      for (let i = 0; i < l.len; i++) M[l.base + i] = (M[l.base + i] * l.mul + l.add) % M16;
      break;
    case 'swap':
      for (let i = 0; i < l.len; i++) {
        const t = M[l.a + i];
        M[l.a + i] = M[l.b + i];
        M[l.b + i] = t;
      }
      break;
  }
}

function applyLayerInverse(M: number[], l: DeserLayer): void {
  switch (l.kind) {
    case 'xor':
      applyLayerForward(M, l); // XOR is an involution
      break;
    case 'transform': {
      const inv = modInverse16(l.mul);
      for (let i = 0; i < l.len; i++) M[l.base + i] = mod((M[l.base + i] - l.add) * inv, M16);
      break;
    }
    case 'swap':
      applyLayerForward(M, l); // swap is an involution
      break;
  }
}

/* --------------------------------------------------------------------------
 * Program
 * ------------------------------------------------------------------------*/

export interface DeserProgram {
  /** Flat [op,a,b,c, ...] using the DESER VM's WIRE opcodes. */
  flat: number[];
  /** The baked payload (already inverse-transformed). */
  data: number[];
  /** Layers the VM will apply, in order. */
  layers: DeserLayer[];
  /** deserEncode[canonical] = wire */
  deserEncode: number[];
  /** deserDecode[wire] = canonical */
  deserDecode: number[];
  /** Region map for tooling / the check script. */
  regions: DeserRegions;
}

export interface DeserRegions {
  opsRun: [number, number];
  aRun: [number, number];
  bRun: [number, number];
  cRun: [number, number];
  constRun: [number, number];
  protoRun: [number, number];
}

export interface DeserCompileInput {
  /** de-interleaved encrypted instruction words: all op-words, then A, B, C */
  opRun: number[];
  aRun: number[];
  bRun: number[];
  cRun: number[];
  /** encrypted constant byte stream for the entrypoint proto */
  constRun: number[];
  /** flat per-proto metadata records */
  protoRun: number[];
  entrypoint: number;
  ninstr: number;
  maxRegs: number;
  nParams: number;
  isVararg: boolean;
  macLo: number;
  macHi: number;
  seed: number;
  rng: () => number;
  /** how much chaff to weave into the program (0..1). Default 0.35 */
  chaffRatio?: number;
  /** reconstruction layers. Default: randomly generated. */
  layers?: DeserLayer[];
}

function permute(range: number, rng: () => number): number[] {
  const t = Array.from({ length: range }, (_, i) => i);
  for (let i = range - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = t[i];
    t[i] = t[j];
    t[j] = tmp;
  }
  return t;
}

function invert(encode: number[]): number[] {
  const inv = new Array<number>(encode.length).fill(0);
  for (let i = 0; i < encode.length; i++) inv[encode[i]] = i;
  return inv;
}

/** Build random reconstruction layers that stay inside `total` memory cells. */
function randomLayers(total: number, rng: () => number, count: number): DeserLayer[] {
  const layers: DeserLayer[] = [];
  for (let i = 0; i < count; i++) {
    const pick = Math.floor(rng() * 3);
    const len = 1 + Math.floor(rng() * Math.min(64, Math.max(1, total)));
    const base = Math.floor(rng() * Math.max(1, total - len));
    if (pick === 0) {
      layers.push({ kind: 'xor', base, key: Math.floor(rng() * 256), len });
    } else if (pick === 1) {
      // odd multiplier keeps it invertible mod 2^16
      const mul = 1 + 2 * Math.floor(rng() * 32767);
      layers.push({ kind: 'transform', base, mul, add: Math.floor(rng() * M16), len });
    } else {
      const b = Math.floor(rng() * Math.max(1, total - len));
      layers.push({ kind: 'swap', a: base, b, len });
    }
  }
  return layers;
}

/**
 * Compile a deserialization program.
 *
 * The returned `data` is the payload to ship: it is the plaintext region
 * layout with the INVERSE of every layer applied, so that running the layers
 * forward reconstructs the real values.
 */
export function compileDeserProgram(input: DeserCompileInput): DeserProgram {
  const rng = input.rng;

  const opRun = input.opRun.slice();
  const aRun = input.aRun.slice();
  const bRun = input.bRun.slice();
  const cRun = input.cRun.slice();
  const constRun = input.constRun.slice();
  const protoRun = input.protoRun.slice();

  // Payload layout: [ops][A][B][C][consts][protos][scalars]
  const scalarCount = 7;
  const oOps = 0;
  const oA = oOps + opRun.length;
  const oB = oA + aRun.length;
  const oC = oB + bRun.length;
  const oConst = oC + cRun.length;
  const oProto = oConst + constRun.length;
  const oScalar = oProto + protoRun.length;
  const total = oScalar + scalarCount;

  const M: number[] = new Array(total).fill(0);
  const put = (src: number[], off: number) => {
    for (let i = 0; i < src.length; i++) M[off + i] = src[i];
  };
  put(opRun, oOps);
  put(aRun, oA);
  put(bRun, oB);
  put(cRun, oC);
  put(constRun, oConst);
  put(protoRun, oProto);

  M[oScalar + 0] = input.entrypoint;
  M[oScalar + 1] = input.ninstr;
  M[oScalar + 2] = input.maxRegs;
  M[oScalar + 3] = input.nParams;
  M[oScalar + 4] = input.isVararg ? 1 : 0;
  M[oScalar + 5] = input.macLo & 0xffff;
  M[oScalar + 6] = input.macHi & 0xffff;

  const layers =
    input.layers ??
    randomLayers(total, rng, 12 + Math.floor(rng() * 12));

  // Bake payload = L1^-1(L2^-1(...Ln^-1(plain)))
  const baked = M.slice();
  for (let i = layers.length - 1; i >= 0; i--) applyLayerInverse(baked, layers[i]);

  // ---- emit the program -------------------------------------------------
  const encode = permute(DESER_OPCODE_COUNT, xorshift32(input.seed >>> 0));
  const decode = invert(encode);
  const flat: number[] = [];

  const emit = (op: DeserOp, a: number, b: number, c: number) => {
    flat.push(encode[op], a & 0xffff, b & 0xffff, c & 0xffff);
  };

  const chaffRatio = input.chaffRatio ?? 0.35;
  const chaff = () => rng() < chaffRatio;
  const junkCount = Math.floor(rng() * 3) + 1;

  // dead preamble: LOAD_BYTE into scratch cells that are never read
  for (let j = 0; j < junkCount && chaff(); j++) {
    emit(DeserOp.LOAD_BYTE, total + 1 + j, Math.floor(rng() * 256), 0);
  }

  // ---- reconstruction ---------------------------------------------------
  for (const l of layers) {
    if (l.kind === 'xor') emit(DeserOp.XOR_RANGE, l.base, l.key, l.len);
    else if (l.kind === 'transform') emit(DeserOp.TRANSFORM_TABLE, l.base, l.mul, l.add);
    else emit(DeserOp.SWAP_RANGE, l.a, l.b, l.len);

    // dead branch: the guard cell lives past the payload so it reads as nil,
    // and the target is the immediately following instruction anyway, so this
    // is a no-op even if a tampered build makes the guard read as 0.
    if (chaff()) emit(DeserOp.JMP_IF_ZERO, total + 1, flat.length / 4 + 1, 0);
    if (chaff()) emit(DeserOp.JMP, flat.length / 4 + 1, 0, 0);
  }

  // ---- copy runs into the output arrays ---------------------------------
  const copyRun = (field: number, off: number, len: number) => {
    if (len <= 0) {
      emit(DeserOp.COPY_BLOCK, field, off, 0);
      return;
    }
    // chunked so no single instruction has an obvious whole-table length
    let done = 0;
    while (done < len) {
      const step = Math.min(len - done, 64 + Math.floor(rng() * 192));
      emit(DeserOp.COPY_BLOCK, field, off + done, step);
      done += step;
      if (chaff() && done < len) emit(DeserOp.JMP, flat.length / 4 + 1, 0, 0);
    }
  };

  copyRun(DESER_FIELD.INSTS, oOps, opRun.length);
  copyRun(DESER_FIELD.REG_A, oA, aRun.length);
  copyRun(DESER_FIELD.REG_B, oB, bRun.length);
  copyRun(DESER_FIELD.REG_C, oC, cRun.length);
  copyRun(DESER_FIELD.CONSTANTS, oConst, constRun.length);
  copyRun(DESER_FIELD.PROTOTYPES, oProto, protoRun.length);

  // ---- scalars -----------------------------------------------------------
  const scalarMap: [number, number][] = [
    [DESER_FIELD.ENTRYPOINT, oScalar + 0],
    [DESER_FIELD.NINSTR, oScalar + 1],
    [DESER_FIELD.MAXREGS, oScalar + 2],
    [DESER_FIELD.NPARAMS, oScalar + 3],
    [DESER_FIELD.VARARG, oScalar + 4],
    [DESER_FIELD.MAC_LO, oScalar + 5],
    [DESER_FIELD.MAC_HI, oScalar + 6],
  ];
  // scrambled order (v13.6 "scrambled constant order")
  const order = scalarMap.slice();
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = order[i];
    order[i] = order[j];
    order[j] = t;
  }
  for (const [field, cell] of order) {
    emit(DeserOp.WRITE_FIELD, field, cell, 0);
    if (chaff()) emit(DeserOp.LOAD_BYTE, total + 2, Math.floor(rng() * 256), 0);
  }

  // ---- anti-tamper result + halt ----------------------------------------
  emit(DeserOp.HALT, 0, 0, 0);

  return {
    flat,
    data: baked,
    layers,
    deserEncode: encode,
    deserDecode: decode,
    regions: {
      opsRun: [oOps, opRun.length],
      aRun: [oA, aRun.length],
      bRun: [oB, bRun.length],
      cRun: [oC, cRun.length],
      constRun: [oConst, constRun.length],
      protoRun: [oProto, protoRun.length],
    },
  };
}

/** Verify the program reconstructs the expected regions (check script). */
export function runDeserProgram(prog: DeserProgram): {
  scalars: Record<string, number>;
  arrays: Record<string, number[]>;
} {
  const M = prog.data.slice();
  const arrays: Record<string, number[]> = {
    [DESER_FIELD.INSTS]: [],
    [DESER_FIELD.REG_A]: [],
    [DESER_FIELD.REG_B]: [],
    [DESER_FIELD.REG_C]: [],
    [DESER_FIELD.CONSTANTS]: [],
    [DESER_FIELD.PROTOTYPES]: [],
    [DESER_FIELD.UPVALUES]: [],
  };
  const scalars: Record<string, number> = {};

  let pc = 0;
  const guard = prog.flat.length * 4 + 64;
  let steps = 0;
  while (pc * 4 < prog.flat.length && steps++ < guard) {
    const base = pc * 4;
    const op = prog.deserDecode[prog.flat[base]];
    const a = prog.flat[base + 1];
    const b = prog.flat[base + 2];
    const c = prog.flat[base + 3];
    switch (op) {
      case DeserOp.LOAD_BYTE:
        M[a] = b & 0xff;
        break;
      case DeserOp.XOR_RANGE:
        for (let i = 0; i < c; i++) M[a + i] = (M[a + i] ^ b) & 0xff;
        break;
      case DeserOp.SWAP_RANGE:
        for (let i = 0; i < c; i++) {
          const t = M[a + i];
          M[a + i] = M[b + i];
          M[b + i] = t;
        }
        break;
      case DeserOp.COPY_BLOCK: {
        const dst = arrays[a];
        if (!dst) throw new Error(`Xanax/DeserCompiler: bad array field ${a}`);
        for (let i = 0; i < c; i++) dst.push(M[b + i]);
        break;
      }
      case DeserOp.WRITE_FIELD:
        scalars[String(a)] = M[b];
        break;
      case DeserOp.TRANSFORM_TABLE:
        for (let i = 0; i < c; i++) M[a + i] = (M[a + i] * b + c) % M16;
        break;
      case DeserOp.JMP:
        pc = a;
        continue;
      case DeserOp.JMP_IF_ZERO:
        if (M[a] === 0) {
          pc = b;
          continue;
        }
        break;
      case DeserOp.HALT:
        pc = Infinity;
        continue;
      default:
        throw new Error(`Xanax/DeserCompiler: bad deser opcode ${op}`);
    }
    pc++;
  }

  return { scalars, arrays };
}

/* ==========================================================================
 * LUAU EMISSION
 * ==========================================================================*/

export interface DeserEmitCtx {
  nm: (hint: string) => string;
  /** bit32 aliases from the bootstrap */
  nBxor: string;
  nBand: string;
  /** name of the payload table (1-based flat array) */
  nData: string;
  /** name of the program table (1-based flat array) */
  nProgram: string;
  /** name of the deserialized output table to produce */
  nOut: string;
  /** optional MAC verifier local (STEP 2.6 anti-tamper during reconstruct) */
  nMacFn?: string;
}

/**
 * Emit the Stage-1 interpreter.  It has its own shuffled opcode table and its
 * own dispatch loop - it shares NOTHING with the Real VM's decoder, so a
 * tooling author has to reverse two unrelated ISAs.
 */
export function emitDeserInterpreterLua(ctx: DeserEmitCtx): string {
  const { nm, nBxor, nData, nProgram, nOut } = ctx;
  const nRun = nm('deserRun');
  const nM = nm('mem');
  const nPc = nm('pc');
  const nD = nm('dd');
  const nIns = nm('ins');
  const nOp = nm('dop');
  const nA = nm('da');
  const nB = nm('db');
  const nC = nm('dc');
  const nI = nm('dix');
  const nT = nm('dtmp');
  const nArr = nm('arr');
  const nMac = ctx.nMacFn;

  const lines: string[] = [];
  lines.push(`-- Stage 1: deserialization VM (STEP 2)`);
  lines.push(`local ${nD}={${Array.from({ length: DESER_OPCODE_COUNT }, (_, i) => i).map((_, canonical) => `${canonical + 1}=${canonical + 1}`).join(',')}}`);
  lines.push(`-- (the real decode table is patched in by emitDeserDecodeTableLua)`);
  lines.push(`local function ${nRun}(data,prog)`);
  lines.push(` local ${nM}=data`);
  lines.push(` local ${nOut}={}`);
  lines.push(` local ${nArr}={}`);
  lines.push(` for _0f=${DESER_FIELD.INSTS},${DESER_FIELD.UPVALUES} do ${nArr}[_0f]={} end`);
  lines.push(` local ${nPc}=1`);
  lines.push(` while true do`);
  lines.push(`  local ${nI}=(${nPc}-1)*4`);
  lines.push(`  local ${nIns}=${nProgram}[${nI}+1]`);
  lines.push(`  local ${nOp}=${nD}[${nIns}]`);
  lines.push(`  local ${nA}=${nProgram}[${nI}+2]`);
  lines.push(`  local ${nB}=${nProgram}[${nI}+3]`);
  lines.push(`  local ${nC}=${nProgram}[${nI}+4]`);
  lines.push(`  if ${nOp}==${DeserOp.LOAD_BYTE + 1} then`);
  lines.push(`   ${nM}[${nA}]=${nB}`);
  lines.push(`  elseif ${nOp}==${DeserOp.XOR_RANGE + 1} then`);
  lines.push(`   for _0k=0,${nC}-1 do ${nM}[${nA}+_0k]=${nBxor}(${nM}[${nA}+_0k],${nB}) end`);
  lines.push(`  elseif ${nOp}==${DeserOp.SWAP_RANGE + 1} then`);
  lines.push(`   for _0k=0,${nC}-1 do local ${nT}=${nM}[${nA}+_0k] ${nM}[${nA}+_0k]=${nM}[${nB}+_0k] ${nM}[${nB}+_0k]=${nT} end`);
  lines.push(`  elseif ${nOp}==${DeserOp.COPY_BLOCK + 1} then`);
  lines.push(`   local dst=${nArr}[${nA}]`);
  lines.push(`   for _0k=0,${nC}-1 do dst[#dst+1]=${nM}[${nB}+_0k] end`);
  lines.push(`  elseif ${nOp}==${DeserOp.WRITE_FIELD + 1} then`);
  lines.push(`   ${nOut}[${nA}]=${nM}[${nB}]`);
  lines.push(`  elseif ${nOp}==${DeserOp.TRANSFORM_TABLE + 1} then`);
  lines.push(`   for _0k=0,${nC}-1 do ${nM}[${nA}+_0k]=(${nM}[${nA}+_0k]*${nB}+${nC})%65536 end`);
  lines.push(`  elseif ${nOp}==${DeserOp.JMP + 1} then`);
  lines.push(`   ${nPc}=${nA}`);
  lines.push(`  elseif ${nOp}==${DeserOp.JMP_IF_ZERO + 1} then`);
  lines.push(`   if ${nM}[${nA}]==0 then ${nPc}=${nB} else ${nPc}=${nPc}+1 end`);
  lines.push(`  else`);
  lines.push(`   break`);
  lines.push(`  end`);
  lines.push(`  ${nPc}=${nPc}+1`);
  if (nMac) {
    lines.push(`  -- STEP 2.6: anti-tamper enforced DURING reconstruction`);
    lines.push(`  if (${nPc}%512)==0 then ${nMac}(${nM}) end`);
  }
  lines.push(` end`);
  lines.push(` return ${nOut},${nArr}`);
  lines.push(`end`);
  lines.push(`-- call site: local out,arr = ${nRun}(${nData},${nProgram})`);
  return lines.join('\n');
}

/**
 * Emit the deser VM's own (shuffled) opcode decode table and overwrite the
 * identity table the interpreter starts with.
 */
export function emitDeserDecodeTableLua(
  nm: (hint: string) => string,
  prog: DeserProgram,
  nD: string
): string {
  const parts = 2;
  const size = Math.ceil(DESER_OPCODE_COUNT / parts);
  const names: string[] = [];
  const lines: string[] = [];
  for (let p = 0; p < parts; p++) {
    const lo = p * size;
    const hi = Math.min(DESER_OPCODE_COUNT, lo + size);
    if (lo >= hi) break;
    const entries: string[] = [];
    for (let w = lo; w < hi; w++) {
      // +1 because the interpreter indexes the table by the wire opcode
      entries.push(`${w + 1}=${prog.deserDecode[w] + 1}`);
    }
    const pn = nm('dsp');
    names.push(pn);
    lines.push(`local ${pn}={${entries.join(',')}}`);
  }
  // NOTE: iterate each part table directly.  Wrapping them in `{...}` would
  // make an array OF tables and the merge would copy the tables, not the keys.
  for (const pn of names) {
    lines.push(`for _0k,_0v in next,${pn} do ${nD}[_0k]=_0v end`);
  }
  return lines.join('\n');
}

/**
 * Emit the program + payload as Luau table literals, split into chunks that
 * are merged at runtime so no single literal contains the whole thing.
 */
export function emitDeserDataLua(
  nm: (hint: string) => string,
  prog: DeserProgram,
  targetData: string,
  targetProgram: string
): string {
  const lines: string[] = [];

  const dump = (values: number[], out: string): void => {
    const chunkSize = 200;
    const parts: string[] = [];
    for (let i = 0; i < values.length; i += chunkSize) {
      const pn = nm('dz');
      parts.push(pn);
      lines.push(`local ${pn}={${values.slice(i, i + chunkSize).join(',')}}`);
    }
    lines.push(`local ${out}={}`);
    for (const pn of parts) {
      lines.push(`for _0k,_0v in next,${pn} do ${out}[#${out}+1]=_0v end`);
    }
  };

  dump(prog.data, targetData);
  dump(prog.flat, targetProgram);
  return lines.join('\n');
}

/** Flatten a proto tree into the runs the DeserCompiler wants. */
export function flattenRegTree(
  root: RegBytecodeChunk
): { protoRun: number[]; uidOrder: number[] } {
  const protoRun: number[] = [];
  const uidOrder: number[] = [];
  const visit = (c: RegBytecodeChunk, parentUid: number) => {
    const uid = c.uid ?? protoRun.length;
    uidOrder.push(uid);
    const nInstr = c.nInstructions;
    protoRun.push(
      uid,
      parentUid,
      nInstr,
      c.maxRegs,
      c.nParams,
      c.isVararg ? 1 : 0,
      c.K.length,
      c.protos ? c.protos.length : 0,
      c.upvalues ? c.upvalues.length : 0
    );
    if (c.protos) for (const p of c.protos) visit(p, uid);
  };
  visit(root, -1);
  return { protoRun, uidOrder };
}
