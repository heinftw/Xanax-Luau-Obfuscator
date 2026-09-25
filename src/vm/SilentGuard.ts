/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/SilentGuard.ts
 * PART 1 / STEP 4 : SILENT REGISTER POISONING
 * ----------------------------------------------------------------------------
 * Stock behaviour: the bootstrap's anti-tamper (nEnvInteg / nAntiDbg /
 * nMutate) uses explicit, catchable branches:
 *
 *     if not keyInteg() or not sboxInteg() then mutate() end
 *     if verify(dec) ~= checksum then mutate() dec = decrypt(raw) end
 *
 * That is an oracle.  An attacker hooks `mutate`, forces the comparison true,
 * or wraps the whole thing in pcall and reads the error.  birk.blog on
 * Luraph: "no comparison, no branch, no oracle to probe".
 *
 * New behaviour - every integrity result is folded into the rolling key:
 *
 *   1. A CBC-MAC is computed over the first MAC_WINDOW words of the
 *      deserialized code table and stored as two 32-bit constants.
 *   2. Inside the dispatch loop, the chain periodically (chain & 0x1F == 0)
 *      recomputes the MAC over the CURRENT code table.
 *   3. A mismatch XORs the chain with 0xFF.  Every subsequent opcode
 *      decryption is silently wrong.  No error.  No branch.  No pcall.
 *   4. The whole check reads like innocuous arithmetic on locals with
 *      boring names.
 *   5. When the VM finishes, keys / round keys / code tables are zeroed.
 *
 * The select is done with integer division, never with `and/or`:
 *
 *     d = bxor(a1, c1) + bxor(a2, c2)      -- 0  <=>  MAC matches
 *     m = 1 // (1 + d)                     -- 1 if match, else 0
 *     chain = bxor(chain, 255 * (1 - m))   -- 0 or 0xFF
 *
 * d is always >= 0 because it is a sum of two bxor results, so the division
 * is exact and total.  There is no branch to patch.
 * ==========================================================================*/

export const SILENT_MAGIC = {
  MAC_X0: 0x243f6a88,
  MAC_Y0: 0x85a308d3,
  MAC_AX: 0x9e3779b9,
  MAC_SALT: 0x5c1f0d33,
  PERIOD: 0x1f,
  POISON: 0xff,
  WINDOW: 32,
} as const;

export type MacPair = [number, number];

const U32 = 0x100000000;

const u = (n: number) => n >>> 0;

/** rotate left by r over 32 bits */
export function rotl32(x: number, r: number): number {
  const a = u(x);
  return u(((a << r) | (a >>> (32 - r))) & 0xffffffff);
}

/**
 * CBC-MAC-ish two-lane checksum.  One round per word, no multiplies anywhere
 * so the Luau half can be emitted with plain bit32 calls.
 */
export function cbMac(words: number[], window = SILENT_MAGIC.WINDOW): MacPair {
  let x = SILENT_MAGIC.MAC_X0 >>> 0;
  let y = SILENT_MAGIC.MAC_Y0 >>> 0;
  const n = Math.min(window, words.length);
  for (let i = 0; i < n; i++) {
    const v = u(words[i] & 0xffff);
    const a = u(x ^ v);
    const b = rotl32(x, 7);
    x = u((a + b + SILENT_MAGIC.MAC_AX) % U32);
    const t = u((y + x) % U32);
    y = rotl32(t, 11);
    y = u(y ^ ((x >>> 7) | SILENT_MAGIC.MAC_SALT));
  }
  return [u(x), u(y)];
}

/** Convenience for the deserialization stage. */
export function macOverCodeTable(code: number[]): MacPair {
  return cbMac(code, SILENT_MAGIC.WINDOW);
}

/* --------------------------------------------------------------------------
 * Luau emission
 * ------------------------------------------------------------------------*/

export interface SilentEmitCtx {
  nm: (hint: string) => string;
  nBxor: string;
  nBand: string;
  nLshift: string;
  nRshift: string;
  nBor: string;
  /** local holding the (1-based) code/Insts table to MAC */
  nCode: string;
  /** the rolling chain local used by the dispatch loop */
  nChain: string;
}

/**
 * Emits the MAC function.  Innocuous name, boring locals, reads like a
 * checksum helper (which is exactly what it is).
 */
export function emitMacFunctionLua(ctx: SilentEmitCtx): { fnName: string; code: string } {
  const { nm, nBxor, nLshift, nRshift, nBor, nCode } = ctx;
  const fn = nm('_vs');
  const i = nm('_vi');
  const x = nm('_vx');
  const y = nm('_vy');
  const v = nm('_vv');
  const a = nm('_va');
  const b = nm('_vb');
  const t = nm('_vt');

  return {
    fnName: fn,
    code: [
      `local function ${fn}(${nCode})`,
      ` local ${x}=${SILENT_MAGIC.MAC_X0}`,
      ` local ${y}=${SILENT_MAGIC.MAC_Y0}`,
      ` local ${i}=1`,
      ` while ${i}<=${SILENT_MAGIC.WINDOW} and ${i}<=#${nCode} do`,
      `  local ${v}=${nCode}[${i}]%65536`,
      `  local ${a}=${nBxor}(${x},${v})`,
      `  local ${b}=${nBor}(${nLshift}(${x}%4294967296,7),${nRshift}(${x},25))`,
      `  ${x}=(${a}+${b}+${SILENT_MAGIC.MAC_AX})%4294967296`,
      `  local ${t}=(${y}+${x})%4294967296`,
      `  ${y}=${nBxor}(${nBor}(${nLshift}(${t},11),${nRshift}(${t},21)),${nBxor}(${nRshift}(${x},7),${SILENT_MAGIC.MAC_SALT}))`,
      `  ${i}=${i}+1`,
      ` end`,
      ` return ${x},${y}`,
      `end`,
    ].join('\n'),
  };
}

/**
 * The poisoning snippet.  Paste this INSIDE the dispatch loop of
 * buildVMRuntime(), right after `chain` has been used to decode the opcode.
 *
 * `c1` / `c2` are the two stored 32-bit MAC halves.
 */
export function emitSilentPoisonLua(
  ctx: SilentEmitCtx,
  macFn: string,
  c1: number,
  c2: number,
  nCodeTable: string
): string {
  const { nm, nBxor, nBand, nChain } = ctx;
  const a1 = nm('_qa');
  const a2 = nm('_qb');
  const d = nm('_qd');
  const m = nm('_qm');

  return [
    `-- periodic re-key (innocuous arithmetic, no oracle)`,
    `if ${nBand}(${nChain},${SILENT_MAGIC.PERIOD})<1 then`,
    ` local ${a1},${a2}=${macFn}(${nCodeTable})`,
    ` local ${d}=${nBxor}(${a1},${c1 >>> 0})+${nBxor}(${a2},${c2 >>> 0})`,
    ` local ${m}=1//(1+${d})`,
    ` ${nChain}=${nBxor}(${nChain},${SILENT_MAGIC.POISON}*(1-${m}))`,
    `end`,
  ].join('\n');
}

/**
 * Replacement for the old `if not keyInteg() then mutate() end` pattern.
 * Any number of boolean integrity results can be folded in; a false one
 * poisons the chain instead of raising anything.
 */
export function emitSilentIntegrityLua(
  ctx: SilentEmitCtx,
  conditions: string[]
): string {
  const { nm, nBxor, nChain } = ctx;
  const d = nm('_id');
  const m = nm('_im');
  const parts = conditions.map((c) => `(${c} and 0 or 1)`).join('+');
  return [
    `local ${d}=${parts.length === 0 ? '0' : parts}`,
    `local ${m}=1//(1+${d})`,
    `${nChain}=${nBxor}(${nChain},${SILENT_MAGIC.POISON}*(1-${m}))`,
  ].join('\n');
}

/**
 * STEP 4.5 - zeroise key material once the VM has finished.
 * Drop this at the end of the bootstrap's exec state.
 */
export function emitZeroizeLua(
  nm: (hint: string) => string,
  tables: string[],
  scalars: string[]
): string {
  const i = nm('_zi');
  const j = nm('_zj');
  const lines: string[] = [];
  for (const t of tables) {
    lines.push(`for ${i}=1,#${t} do ${t}[${i}]=0 end`);
  }
  for (const s of scalars) {
    lines.push(`${s}=0`);
  }
  // second pass with a different induction variable: an optimiser cannot
  // merge the two loops without proving they are identical, and they are not
  // (this one also truncates).
  for (const t of tables) {
    lines.push(`for ${j}=#${t},1,-1 do ${t}[${j}]=0 end`);
    lines.push(`${t}={}`);
  }
  return lines.join('\n');
}

/**
 * Drop the deserialization interpreter + payload so the GC can reclaim them
 * the moment the Real VM owns the data (single-VM-at-a-time handoff).
 */
export function emitDropDeserLua(
  deserLocals: string[]
): string {
  const lines: string[] = [];
  for (const s of deserLocals) {
    lines.push(`${s}=nil`);
  }
  lines.push(`_G.collectgarbage and collectgarbage("step")`);
  return lines.join('\n');
}

/* --------------------------------------------------------------------------
 * Self checks for real_check-script
 * ------------------------------------------------------------------------*/

/** The MAC must be stable and sensitive. */
export function roundTripMac(): boolean {
  const a = cbMac([1, 2, 3, 4, 5, 6, 7, 8]);
  const b = cbMac([1, 2, 3, 4, 5, 6, 7, 8]);
  if (a[0] !== b[0] || a[1] !== b[1]) return false;
  const c = cbMac([1, 2, 3, 4, 5, 6, 7, 9]);
  return c[0] !== a[0] || c[1] !== a[1];
}

/**
 * Prove the poison expression is exactly a branchless equality test.
 * Used by the check script so nobody "simplifies" it into an if.
 */
export function poisonValue(match: boolean): number {
  const d = match ? 0 : 7;
  const m = Math.floor(1 / (1 + d));
  return (SILENT_MAGIC.POISON * (1 - m)) & 0xff;
}
