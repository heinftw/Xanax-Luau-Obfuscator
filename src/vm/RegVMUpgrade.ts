/* ============================================================================
 * XANAX / CLYDE OBFUSCATOR - src/vm/RegVMUpgrade.ts
 * ----------------------------------------------------------------------------
 * STEP 1 WIRED FOR REAL.  This is the patch module for reg-vm-gen.ts.
 *
 * It was written against the actual generateRegVM() in your repo, using the
 * real call sites:
 *
 *     const mappedCode = doShuffle
 *         ? mapRegBytecode(chunk.code, encode, ctx.argPerm)
 *         : chunk.code;
 *     const dataC = serializeRegCode(mappedCode, ctx);
 *     const dataP = serializeRegProtos(chunk.protos, ctx);
 *
 * and the real CLOSURE handler signature:
 *
 *     R[A+1]=function(...)
 *       return run(proto[gK],proto[gC],proto[gP],nU,proto[gN],
 *                  proto[gMR],proto[gVA],env,...)
 *     end
 *
 * Nothing in here touches code you did not show me.  Every hook point is
 * given as literal anchor text you can Ctrl+F for.
 * ==========================================================================*/

import type { RegBytecodeChunk } from './bytecode.js';
import { REG_OPCODE_COUNT } from './bytecode.js';
import { walkProtoTree, invertPermutation, xorshift32 } from './ProtoKeygen.js';

/* --------------------------------------------------------------------------
 * What we add to each proto
 * ------------------------------------------------------------------------*/

export interface ProtoOpcodeEntry {
  uid: number;
  depth: number;
  treeIndex: number;
  encode: number[];
  decode: number[];
}

declare module './bytecode.js' {
  interface RegBytecodeChunk {
    /** wire opcode emitted for canonical opcode i (this proto only) */
    opEncode?: number[];
    /** inverse of opEncode */
    opDecode?: number[];
    uid?: number;
    depth?: number;
    treeIndex?: number;
    perProtoApplied?: boolean;
  }
}

/* --------------------------------------------------------------------------
 * 1. THE ONLY LINE YOU MUST ADD IN generateRegVM()
 * --------------------------------------------------------------------------
 *
 * ANCHOR:  const mappedCode = doShuffle
 *
 * Put this immediately BEFORE that line:
 *
 *     import { applyPerProtoOpcodes } from './RegVMUpgrade.js';
 *     ...
 *     const perProto = applyPerProtoOpcodes(chunk, seed, doShuffle);
 *
 * Then change the anchor line to:
 *
 *     const mappedCode = doShuffle
 *         ? mapRegBytecode(chunk.code, chunk.opEncode!, ctx.argPerm)
 *         : chunk.code;
 *
 * (chunk.opEncode is the ROOT proto's own table, set by the call above.)
 * ------------------------------------------------------------------------*/

export function applyPerProtoOpcodes(
  root: RegBytecodeChunk,
  masterSeed: number,
  enabled: boolean
): ProtoOpcodeEntry[] {
  if (!enabled) {
    // Identity tables: debug bytecode is not remapped, so decode must be a no-op.
    const refs = walkProtoTree(root, masterSeed, REG_OPCODE_COUNT);
    const ident = Array.from({ length: REG_OPCODE_COUNT }, (_, i) => i);
    for (const r of refs) {
      r.encode = ident;
      r.decode = ident;
      r.chunk.opEncode = ident;
      r.chunk.opDecode = ident;
      r.chunk.perProtoApplied = true;
    }
    return refs;
  }

  const refs = walkProtoTree(root, masterSeed, REG_OPCODE_COUNT);
  for (const r of refs) {
    if (r.chunk.perProtoApplied) continue;
    r.chunk.opEncode = r.encode;
    r.chunk.opDecode = r.decode;
    r.chunk.perProtoApplied = true;
  }
  return refs;
}

/* --------------------------------------------------------------------------
 * 2. serializeRegProtos - add the decode table as an extra field
 * --------------------------------------------------------------------------
 *
 * Your current emitter pushes, per proto:
 *
 *     items.push(`{${sK},${sC},${sP},${sU},${nP},${mR},${isVA}}`);
 *
 * and the keyed form:
 *
 *     items.push(`{${pk.pK}=${sK},... ,${pk.pN}=${nP},mR=${mR},vA=${isVA}}`);
 *
 * Replace both with the helpers below.  The table becomes field 8 (positional)
 * or `dT` (keyed).
 * ------------------------------------------------------------------------*/

/** Positional (level !== "debug"). `p` is the proto, `tableLiteral` from below. */
export function protoItemPositional(
  sK: string,
  sC: string,
  sP: string,
  sU: string,
  nP: number,
  mR: number,
  isVA: boolean,
  tableLiteral: string
): string {
  return `{${sK},${sC},${sP},${sU},${nP},${mR},${isVA},${tableLiteral}}`;
}

/** Keyed (level === "debug"). */
export function protoItemKeyed(
  pk: { pK: string; pC: string; pP: string; pU: string; pN: string },
  sK: string,
  sC: string,
  sP: string,
  sU: string,
  nP: number,
  mR: number,
  isVA: boolean,
  tableLiteral: string
): string {
  return `{${pk.pK}=${sK},${pk.pC}=${sC},${pk.pP}=${sP},${pk.pU}=${sU},` +
    `${pk.pN}=${nP},mR=${mR},vA=${isVA},dT=${tableLiteral}}`;
}

/**
 * Build the per-proto decode table reference.
 *
 * DEPRECATED FORM - do not use.  This emitted the permutation as a plaintext
 * table literal, and a deobfuscator dump showed it verbatim:
 *
 *     (function() local _t={}
 *       for _k,_v in next,{1=15,2=42,3=26,...} do _t[_k+0]=_v-1 end ... end)()
 *
 * That is 57 readable numbers per proto.  Copy the table, win the VM.
 *
 * Use emitDerivedTableRefLua() from DerivedTables.ts instead: it ships only
 * (treeIndex, depth) and the runtime recomputes the permutation from those.
 * Kept only so existing call sites keep compiling while you migrate.
 */
export function serializeProtoDecodeTable(
  p: RegBytecodeChunk,
  rng: () => number
): string {
  const decode = p.opDecode;
  if (!decode) return 'nil';

  const parts = 2 + Math.floor(rng() * 2);
  const size = Math.ceil(decode.length / parts);
  const chunks: string[] = [];

  for (let i = 0; i < parts; i++) {
    const lo = i * size;
    const hi = Math.min(decode.length, lo + size);
    if (lo >= hi) break;
    const entries: string[] = [];
    for (let k = lo; k < hi; k++) entries.push(`[${k - lo + 1}]=${decode[k] + 1}`);
    chunks.push(`{${entries.join(',')}}`);
  }

  if (chunks.length === 1) return chunks[0];

  const merged: string[] = [];
  for (let i = 0; i < chunks.length; i++) {
    merged.push(
      `for _k,_v in next,${chunks[i]} do _t[_k+${i * size}]=_v-1 end`
    );
  }
  return `(function() local _t={} ${merged.join(' ')} return _t end)()`;
}

/* --------------------------------------------------------------------------
 * 3. CLOSURE handler - pass the child's table through
 * --------------------------------------------------------------------------
 *
 * ANCHOR (inside registerHandler(RegOp.CLOSURE, ...)):
 *
 *     `${n.R}[A+1]=function(...) return ${n.run}(proto${gK},proto${gC},`
 *     + `proto${gP},proto${gU} and nU or {},proto${gN},proto${gMR},`
 *     + `proto${gVA},${n.env},...) end `
 *
 * Add the 8th accessor next to gMR/gVA:
 *
 *     const gDT = pos ? "[8]" : ".dT";
 *
 * and append it just before ${n.env}:
 *
 *     `${n.R}[A+1]=function(...) return ${n.run}(proto${gK},proto${gC},`
 *     + `proto${gP},proto${gU} and nU or {},proto${gN},proto${gMR},`
 *     + `proto${gVA},proto${gDT},${n.env},...) end `
 * ------------------------------------------------------------------------*/

export function closureAccessorPositional(): string {
  return '[8]';
}

export function closureAccessorKeyed(): string {
  return '.dT';
}

/* --------------------------------------------------------------------------
 * 4. buildVMRuntime - the dispatch side
 * --------------------------------------------------------------------------
 *
 * `run` gains one parameter.  Wherever the opcode is currently decoded with
 * the single shared table, it now uses the per-call local.
 *
 * If your runtime decodes via something like
 *
 *     local _op = D[ code[ip+1] + 1 ]
 *
 * then `D` becomes a parameter instead of a closure-wide constant:
 *
 *     local function run(K, code, protos, upvalues, nParams, maxRegs,
 *                        isVararg, decodeTable, env, ...)
 *         local D = decodeTable
 *         ...
 *     end
 *
 * and the entry call passes the ROOT table:
 *
 *     return run(dK, dC, dP, {}, nP, mR, isVA, _rootDT, env)
 *
 * Nothing else in the dispatch loop changes: the table is read at exactly the
 * same place, it just is not the same table for every function any more.
 * ------------------------------------------------------------------------*/

/** The root proto's table, for the entry call. */
export function rootDecodeTableLiteral(
  root: RegBytecodeChunk,
  rng: () => number
): string {
  return serializeProtoDecodeTable(root, rng);
}

/* --------------------------------------------------------------------------
 * 5. mapRegBytecode - per-proto instead of global
 * --------------------------------------------------------------------------
 *
 * You do NOT need to change mapRegBytecode itself.  It already takes `encode`
 * as an argument - the bug is only that generateRegVM() passes the ONE global
 * table.  applyPerProtoOpcodes() sets chunk.opEncode on every proto, and the
 * recursive protos are already serialized through serializeRegProtos, so
 * add this inside your proto loop, before you serialize each proto's code:
 *
 *     const protoCode = doShuffle
 *         ? mapRegBytecode(p.code, p.opEncode!, ctx.argPerm)
 *         : p.code;
 *
 * ------------------------------------------------------------------------*/

/* --------------------------------------------------------------------------
 * 6. Self check - call from real_check-script
 * ------------------------------------------------------------------------*/

export function verifyPerProtoIsolation(root: RegBytecodeChunk): {
  ok: boolean;
  reason: string;
  protos: number;
  uniqueTables: number;
} {
  const refs: ProtoOpcodeEntry[] = [];
  const visit = (c: RegBytecodeChunk, depth: number) => {
    if (!c.opEncode || !c.opDecode) {
      refs.push({
        uid: -1,
        depth,
        treeIndex: -1,
        encode: [],
        decode: [],
      });
      return;
    }
    refs.push({
      uid: c.uid ?? -1,
      depth,
      treeIndex: c.treeIndex ?? -1,
      encode: c.opEncode,
      decode: c.opDecode,
    });
    if (c.protos) for (const p of c.protos) visit(p, depth + 1);
  };
  visit(root, 0);

  if (refs.some((r) => r.encode.length === 0)) {
    return { ok: false, reason: 'a proto has no opcode table', protos: refs.length, uniqueTables: 0 };
  }

  // every table must be a valid permutation
  for (const r of refs) {
    const inv = invertPermutation(r.encode);
    for (let i = 0; i < inv.length; i++) {
      if (inv[i] !== r.decode[i]) {
        return { ok: false, reason: 'encode/decode are not inverses', protos: refs.length, uniqueTables: 0 };
      }
    }
  }

  const unique = new Set(refs.map((r) => r.decode.join(','))).size;
  const allUnique = unique === refs.length;

  return {
    ok: refs.length === 1 || allUnique,
    reason:
      refs.length === 1
        ? 'single proto - isolation is vacuous'
        : allUnique
          ? 'every proto has a distinct opcode table'
          : `${refs.length - unique} protos share a table`,
    protos: refs.length,
    uniqueTables: unique,
  };
}

/** Deterministic wrapper for tests. */
export function perProtoFromSeed(seed: number): () => number {
  return xorshift32(seed);
}
