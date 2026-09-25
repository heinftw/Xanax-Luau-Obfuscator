/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/ProtoKeygen.ts
 * PART 1 / STEP 1 : PER-FUNCTION OPCODE ISOLATION
 * ----------------------------------------------------------------------------
 * Stock behaviour: shuffleOpcodes() builds ONE encode/decode pair and
 * mapRegChunk() applies it to every proto, so all functions share a single
 * opcode map.  One dump gives an attacker the whole VM.
 *
 * New behaviour: every proto gets its OWN permutation derived from
 *     subkey = masterSeed + treeIndex + depth   (salted, non-obvious magic)
 * The bootstrap captures the right decode table as an upvalue when a closure
 * is created, and the dispatch loop consults that local before every decode.
 *
 * INTEGRATION (reg-vm-gen.ts):
 *   - in serializeRegProtos(): replace the single shuffleOpcodes() call with
 *         const maps = buildProtoOpcodeMaps(root, masterSeed);
 *         applyPerProtoOpcodes(root, maps);
 *     then emit the per-proto tables with emitProtoDecodeTables().
 *   - in mapRegChunk(): take the proto's own `opEncode` instead of the shared
 *     table (see mapRegChunkIsolated below - it is a drop-in).
 *   - in the CLOSURE handler: capture `D[protoUID]` as an upvalue on the
 *     closure (see emitClosureUpvalueCapture).
 * ==========================================================================*/

import {
  RegBytecodeChunk,
  REG_OPCODE_COUNT,
  RegOp,
} from './bytecode.js';

/* --------------------------------------------------------------------------
 * PRNG - deterministic, seedable, no dependencies.
 * ------------------------------------------------------------------------*/

export function xorshift32(seed: number): () => number {
  let s = seed >>> 0;
  if (s === 0) s = 0x9e3779b9;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0x100000000;
  };
}

/* Magic salts.  v14.2: "changed magic numbers to break tools".  Do not
 * simplify, do not reorder, do not "clean up". */
export const PROTO_KEY_MAGIC = {
  TREE_SALT: 0x4f2b1c,
  DEPTH_SALT: 0x019d3a,
  MASTER_SALT: 0x7a55c1,
  FINAL_AVALANCHE: 0x2545f491,
} as const;

/**
 * Derive a proto-unique 32-bit subkey.
 * master + treeIndex + depth, avalanche-mixed so consecutive protos do not
 * produce correlated permutations.
 */
export function deriveProtoSeed(
  masterSeed: number,
  treeIndex: number,
  depth: number
): number {
  let h = (masterSeed ^ PROTO_KEY_MAGIC.MASTER_SALT) >>> 0;
  h = (Math.imul(h ^ (treeIndex + PROTO_KEY_MAGIC.TREE_SALT), 0x85ebca6b) >>> 0);
  h = (h ^ (h >>> 13)) >>> 0;
  h = (Math.imul(h ^ (depth + PROTO_KEY_MAGIC.DEPTH_SALT), 0xc2b2ae35) >>> 0);
  h = (h ^ (h >>> 16)) >>> 0;
  h = (Math.imul(h, 0x27d4eb2f) >>> 0) ^ PROTO_KEY_MAGIC.FINAL_AVALANCHE;
  return h >>> 0;
}

/** Fisher-Yates over 0..count-1 using the supplied stream. */
export function permute(range: number, rng: () => number): number[] {
  const t = Array.from({ length: range }, (_, i) => i);
  for (let i = range - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = t[i];
    t[i] = t[j];
    t[j] = tmp;
  }
  return t;
}

/** encode -> decode inverse.  decode[encode[i]] === i. */
export function invertPermutation(encode: number[]): number[] {
  const inv = new Array<number>(encode.length).fill(0);
  for (let i = 0; i < encode.length; i++) inv[encode[i]] = i;
  return inv;
}

/* --------------------------------------------------------------------------
 * Proto tree walking / identity assignment
 * ------------------------------------------------------------------------*/

export interface ProtoRef {
  chunk: RegBytecodeChunk;
  uid: number;
  treeIndex: number;
  depth: number;
  parentUid: number;
  salt: number;
  encode: number[];
  decode: number[];
}

/** Pre-order walk assigning uid / treeIndex / depth to every proto. */
export function walkProtoTree(
  root: RegBytecodeChunk,
  masterSeed: number,
  count = REG_OPCODE_COUNT
): ProtoRef[] {
  const refs: ProtoRef[] = [];
  let uid = 0;
  let treeIndex = 0;

  const visit = (chunk: RegBytecodeChunk, depth: number, parentUid: number) => {
    const myUid = uid++;
    const myIndex = treeIndex++;
    const salt = deriveProtoSeed(masterSeed, myIndex, depth);
    const rng = xorshift32(salt);
    const encode = permute(count, rng);
    const decode = invertPermutation(encode);

    chunk.uid = myUid;
    chunk.treeIndex = myIndex;
    chunk.depth = depth;

    refs.push({ chunk, uid: myUid, treeIndex: myIndex, depth, parentUid, salt, encode, decode });

    if (chunk.protos) for (const p of chunk.protos) visit(p, depth + 1, myUid);
  };

  visit(root, 0, -1);
  return refs;
}

/**
 * Build every proto's table AND rewrite the code arrays in place.
 * Returns the flat list so the emitter can dump per-proto decode tables.
 *
 * This replaces the "one shuffleOpcodes() + mapRegChunk() for all" flow.
 */
export function buildProtoOpcodeMaps(
  root: RegBytecodeChunk,
  masterSeed: number,
  count = REG_OPCODE_COUNT
): ProtoRef[] {
  const refs = walkProtoTree(root, masterSeed, count);
  for (const r of refs) {
    if (r.chunk.perProtoApplied) continue;
    mapRegChunkIsolated(r.chunk, r.encode);
    r.chunk.perProtoApplied = true;
  }
  return refs;
}

/**
 * Drop-in replacement for mapRegChunk(): applies THIS proto's permutation
 * (not a shared one) to the canonical opcodes sitting in chunk.code.
 */
export function mapRegChunkIsolated(chunk: RegBytecodeChunk, encode: number[]): void {
  const code = chunk.code;
  for (let pos = 0; pos + 3 < code.length; pos += 4) {
    const canonical = code[pos];
    code[pos] = canonical >= 0 && canonical < encode.length ? encode[canonical] : canonical;
  }
}

/** Inverse of mapRegChunkIsolated - used by tooling / dump checking. */
export function unmapRegChunkIsolated(chunk: RegBytecodeChunk, decode: number[]): void {
  const code = chunk.code;
  for (let pos = 0; pos + 3 < code.length; pos += 4) {
    const wire = code[pos];
    code[pos] = wire >= 0 && wire < decode.length ? decode[wire] : wire;
  }
}

/* --------------------------------------------------------------------------
 * Luau emission
 * ------------------------------------------------------------------------*/

export interface LuaNameGen {
  (hint: string): string;
}

function num(n: number): string {
  return String(n >>> 0);
}

/**
 * Emit the per-proto decode tables as Luau.
 *
 * Layout produced (names are supplied by `nm`, everything is a fresh local
 * so nothing collides with the rest of the bootstrap):
 *
 *   local D0={...}            -- proto 0, decode table
 *   ...
 *   local D={<uid0>=D0, ...}  -- uid -> decode table
 *
 * Each table is additionally SPLIT across 2-4 locals and merged, so a static
 * reader cannot lift a full 57-entry permutation in one go.
 */
export function emitProtoDecodeTables(
  refs: ProtoRef[],
  nm: LuaNameGen,
  rng: () => number
): string {
  const lines: string[] = [];
  const uidTableName = nm('protoTables');
  const perProto: string[] = [];

  for (const r of refs) {
    const decode = r.decode;
    const parts = 2 + Math.floor(rng() * 3); // 2..4
    const size = Math.ceil(decode.length / parts);
    const partNames: string[] = [];

    for (let p = 0; p < parts; p++) {
      const lo = p * size;
      const hi = Math.min(decode.length, lo + size);
      if (lo >= hi) break;
      const slice: string[] = [];
      for (let i = lo; i < hi; i++) {
        // store x+1 so 0 stays distinguishable from "missing"
        slice.push(`${i - lo}=${num(decode[i] + 1)}`);
      }
      const pn = nm('pt');
      partNames.push(pn);
      lines.push(`local ${pn}={${slice.join(',')}}`);
    }

    const merged = nm('pd');
    lines.push(`local ${merged}=setmetatable({},{__index=function(_,k) return k end})`);
    // forward decl trick: fill after all parts exist
    const fill: string[] = [];
    let base = 0;
    for (let p = 0; p < partNames.length; p++) {
      const pn = partNames[p];
      fill.push(`for _0k,_0v in next,${pn} do ${merged}[_0k+${base}]=_0v-1 end`);
      base += size;
    }
    lines.push(`do ${fill.join(' ')} end`);
    perProto.push(`[${num(r.uid)}]=${merged}`);
  }

  lines.push(`local ${uidTableName}={` + perProto.join(',') + `}`);
  return lines.join('\n');
}

/**
 * The dispatch-side hook.  `nDecodeTable` is the local that the dispatch loop
 * uses to decode opcodes; `nProtoTables` is the uid-keyed table emitted above.
 *
 * Place this in buildVMRuntime() right where the old code read the single
 * shared decode table.
 */
export function emitDispatchDecodeHook(
  nm: LuaNameGen,
  nProtoTables: string,
  nDecodeTable: string
): string {
  return [
    `-- per-function opcode isolation: decode table is a local that changes on`,
    `-- closure entry, so no two functions agree on what an opcode means.`,
    `local ${nDecodeTable}=${nProtoTables}[0]`,
    `local function ${nm('swapTable')}(uid)`,
    `  local t=${nProtoTables}[uid]`,
    `  if t then ${nDecodeTable}=t end`,
    `  return ${nDecodeTable}`,
    `end`,
  ].join('\n');
}

/**
 * CLOSURE handler body: the closure captures the proto's decode table as an
 * upvalue instead of sharing the caller's.
 *
 * `nProtoTables`   - uid keyed table of decode tables
 * `nMakeClosure`   - the existing closure factory local in buildVMRuntime
 */
export function emitClosureUpvalueCapture(
  nm: LuaNameGen,
  nProtoTables: string,
  nMakeClosure: string,
  nChunkField: string
): string {
  const nTab = nm('closureTable');
  return [
    `local ${nTab}=${nProtoTables}`,
    `-- ${nMakeClosure} must be created with ${nTab} as an upvalue so the child`,
    `-- dispatch loop resolves opcodes through the CHILD's table, not ours.`,
    `local function ${nm('mkClosure')}(protoUID, ${nChunkField})`,
    `  local childDecode=${nTab}[protoUID]`,
    `  return ${nMakeClosure}(${nChunkField}, childDecode, protoUID)`,
    `end`,
  ].join('\n');
}

/** Entry point resolve: which decode table does execution start with. */
export function emitEntrypointDecode(
  nProtoTables: string,
  nEntryUid: number,
  nDecodeTable: string
): string {
  return `local ${nDecodeTable}=(${nProtoTables}[${num(nEntryUid)}] or ${nProtoTables}[0])`;
}

/** Sanity check used by real_check-script: every proto must be unique. */
export function assertUniqueTables(refs: ProtoRef[]): boolean {
  const seen = new Set<string>();
  for (const r of refs) {
    const key = r.decode.join(',');
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return refs.length > 1;
}

/** Which canonical opcodes actually appear in a proto (for dead-opaque ops). */
export function usedOpcodes(chunk: RegBytecodeChunk): Set<RegOp> {
  const used = new Set<RegOp>();
  const code = chunk.code;
  for (let pos = 0; pos + 3 < code.length; pos += 4) used.add(code[pos] as RegOp);
  return used;
}
