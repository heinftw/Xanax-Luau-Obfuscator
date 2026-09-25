/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/MutationTable.ts
 * PART 1 / STEP 8 : OPCODE MUTATION TABLE
 * ----------------------------------------------------------------------------
 * This is a SECOND, independent remapping layer that sits on top of the
 * per-proto opcode permutation (STEP 1):
 *
 *   STEP 1  compile-time  each proto gets its own permutation of the
 *                         canonical opcode space
 *   STEP 8  run-time      a 256-entry table applied to the opcode AFTER the
 *                         chain decryption, BEFORE dispatch
 *
 * So a dump of the static decode tables is not enough - you also need the
 * mutation table, which is itself encrypted with the rolling chain key, so
 * patching any byte of it corrupts dispatch for every later instruction.
 *
 * Table properties:
 *   - entry[X] == Y  ==>  entry[Y] == X   (involutory)
 *   - identity entries are allowed and likely
 *   - the table is emitted SPLIT across several locals and merged at runtime
 * ==========================================================================*/

export const MUTATION_TABLE_SIZE = 256;

export interface MutationTable {
  table: number[];
  swaps: number;
  identities: number;
}

/**
 * Build the table.  `density` in [0,1] controls how many entries get swapped
 * (0 = pure identity, 1 = a derangement-ish permutation).
 */
export function buildMutationTable(rng: () => number, density = 0.28): MutationTable {
  const t = Array.from({ length: MUTATION_TABLE_SIZE }, (_, i) => i);

  // pick a random set of indices and pair them up
  const order = Array.from({ length: MUTATION_TABLE_SIZE }, (_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = order[i];
    order[i] = order[j];
    order[j] = tmp;
  }

  const wanted = Math.floor(MUTATION_TABLE_SIZE * density);
  const usable = wanted - (wanted % 2); // need pairs
  let swaps = 0;
  for (let p = 0; p + 1 < usable; p += 2) {
    const a = order[p];
    const b = order[p + 1];
    if (t[a] !== a || t[b] !== b) continue; // already touched
    t[a] = b;
    t[b] = a;
    swaps++;
  }

  return { table: t, swaps, identities: MUTATION_TABLE_SIZE - swaps * 2 };
}

/** entry[entry[x]] === x must hold for every x. */
export function assertInvolutory(t: number[]): boolean {
  for (let i = 0; i < t.length; i++) {
    const j = t[i];
    if (j < 0 || j >= t.length) return false;
    if (t[j] !== i) return false;
  }
  return true;
}

/** Dispatch-side lookup. */
export function applyMutation(t: number[], op: number): number {
  return op >= 0 && op < t.length ? t[op] : op;
}

/**
 * The chain byte used to encrypt the table.  Must be recomputed identically
 * at runtime, which is why patching the table breaks dispatch.
 */
export function mutationMask(chainSeed: number, slot: number): number {
  return ((chainSeed * 0x1b + slot * 0x5d + 0x3f) & 0xff) >>> 0;
}

export function encryptEntry(value: number, chainSeed: number, slot: number): number {
  return (value ^ mutationMask(chainSeed, slot)) & 0xff;
}

export function decryptEntry(enc: number, chainSeed: number, slot: number): number {
  return (enc ^ mutationMask(chainSeed, slot)) & 0xff;
}

/* --------------------------------------------------------------------------
 * Luau emission
 * ------------------------------------------------------------------------*/

export interface MutationEmitCtx {
  nm: (hint: string) => string;
  nBxor: string;
  /** local holding the chain seed constant (a plain number) */
  nChainSeed: string;
  /** name for the merged table */
  nTable: string;
}

/**
 * Emit the split+encrypted mutation table and the runtime merge loop.
 *
 * Layout:
 *   local _m0={...}   -- encrypted entries [0..63]
 *   local _m1={...}   -- encrypted entries [64..127]
 *   local _m2={...}   -- ...
 *   local MT={}
 *   for k,v in next,_m0 do MT[k]=bit32.bxor(v, mask(k+0)) end
 *   ...
 */
export function emitMutationTableLua(
  ctx: MutationEmitCtx,
  mt: MutationTable,
  rng: () => number,
  parts = 4,
  chainSeed = 0
): string {
  const { nm, nBxor, nChainSeed, nTable } = ctx;
  const table = mt.table;
  const size = Math.ceil(MUTATION_TABLE_SIZE / parts);
  const lines: string[] = [];
  const names: string[] = [];
  const shuffledParts: number[] = Array.from({ length: parts }, (_, i) => i);
  for (let i = shuffledParts.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = shuffledParts[i];
    shuffledParts[i] = shuffledParts[j];
    shuffledParts[j] = tmp;
  }

  const partNames: string[] = [];
  for (let p = 0; p < parts; p++) {
    const pn = nm('mt');
    partNames.push(pn);
    const lo = p * size;
    const hi = Math.min(MUTATION_TABLE_SIZE, lo + size);
    const entries: string[] = [];
    for (let i = lo; i < hi; i++) {
      entries.push(`${i - lo}=${encryptEntry(table[i], chainSeed, i)}`);
    }
    lines.push(`local ${pn}={${entries.join(',')}}`);
  }

  // the *emission* order is shuffled but the *merge* order is fixed, so the
  // dependency between the locals is opaque to a reader
  for (const p of shuffledParts) names.push(partNames[p]);

  lines.push(`local ${nTable}={}`);
  for (let p = 0; p < parts; p++) {
    const pn = partNames[p];
    const base = p * size;
    const k = nm('mk');
    const v = nm('mv');
    lines.push(
      `for ${k},${v} in next,${pn} do ${nTable}[${k}+${base}]=${nBxor}(${v},(${nChainSeed}*27+(${k}+${base})*93+63)%256) end`
    );
  }

  return lines.join('\n');
}

/**
 * The dispatch-side hook.  Place after the opcode has been decrypted and
 * before the dispatch key is formed:
 *
 *     op = MT[op]
 */
export function emitMutationApplyLua(nTable: string, nOp: string): string {
  return `${nOp}=${nTable}[${nOp}] or ${nOp}`;
}

/** Round-trip self check for real_check-script. */
export function roundTripMutation(seedRng: () => number): boolean {
  const mt = buildMutationTable(seedRng, 0.3);
  if (!assertInvolutory(mt.table)) return false;
  for (let i = 0; i < MUTATION_TABLE_SIZE; i++) {
    const enc = encryptEntry(mt.table[i], 0x5a, i);
    if (decryptEntry(enc, 0x5a, i) !== mt.table[i]) return false;
    if (applyMutation(mt.table, applyMutation(mt.table, i)) !== i) return false;
  }
  return true;
}
