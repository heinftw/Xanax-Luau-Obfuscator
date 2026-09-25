/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/Metamorphic.ts
 * PART 1 / STEP 5 : METAMORPHIC DISPATCH VIA METAMETHODS
 * ----------------------------------------------------------------------------
 * birk.blog on Luraph v15:
 *   "the function_prototypes table has a __mod metamethod triggering VM
 *    execution.  Arithmetic handlers invoke code through metamethods when
 *    operands are tables."
 *
 * Luraph history: v12.0 added metamorphic code, v14.2 added more.
 *
 * What this file emits:
 *   1. A dispatch table whose __index metamethod applies the decode
 *      transformation, so the opcode -> handler mapping never exists as a
 *      plain table you can dump.
 *   2. A protos table carrying __mod (and friends) which trigger VM
 *      execution - a hidden second entry point.
 *   3. A CLOSURE handler that creates closures through the metamethod
 *      callback instead of calling the factory directly.
 *   4. An operand-swap registry (MUL swaps B/C etc. - see STEP 7).
 *   5. The metamethod used as the entry point is RANDOMISED PER BUILD, so
 *      a tool written against one build does not work on the next.
 *
 * NOTE on __namecall (Luraph docs): in the generated output `:` calls do NOT
 * invoke __namecall, they invoke __index.  emitNamecallBridgeLua exploits
 * that to hide method resolution behind __index.
 * ==========================================================================*/

import { RegOp } from './bytecode.js';

/* --------------------------------------------------------------------------
 * Operand swap registry (shared with STEP 7)
 * ------------------------------------------------------------------------*/

export type OperandSwap = 'none' | 'BC' | 'CB' | 'AB' | 'AC';

/**
 * Which handlers read their operands in a non-standard order.
 * Must stay in sync with REG_DEVIATIONS in bytecode.ts.
 */
export const OPERAND_SWAPS: Partial<Record<RegOp, OperandSwap>> = {
  [RegOp.MUL]: 'BC',
  [RegOp.TESTSET]: 'CB',
  [RegOp.FUSED_TESTSET_JMP]: 'CB',
  [RegOp.FORPREP]: 'BC',
  [RegOp.FORLOOP]: 'BC',
};

/**
 * Rewrite a handler body so the emitted operand order matches the swap.
 * `body` is a template containing the tokens {A} {B} {C}; the result swaps
 * them.  Mathematically identical for commutative ops, fatal for tools.
 */
export function swapOperands(body: string, swap: OperandSwap): string {
  switch (swap) {
    case 'BC':
    case 'CB':
      return body.replace(/\{B\}/g, '\u0000').replace(/\{C\}/g, '{B}').replace(/\u0000/g, '{C}');
    case 'AB':
      return body.replace(/\{A\}/g, '\u0000').replace(/\{B\}/g, '{A}').replace(/\u0000/g, '{B}');
    case 'AC':
      return body.replace(/\{A\}/g, '\u0000').replace(/\{C\}/g, '{A}').replace(/\u0000/g, '{C}');
    default:
      return body;
  }
}

/** Human-readable registry dump for the check script. */
export function describeOperandSwaps(): string[] {
  const out: string[] = [];
  for (const k of Object.keys(OPERAND_SWAPS)) {
    const op = Number(k) as RegOp;
    out.push(`op=${op} swap=${OPERAND_SWAPS[op]}`);
  }
  return out;
}

/* --------------------------------------------------------------------------
 * Metamethod selection - randomised per build
 * ------------------------------------------------------------------------*/

export type EntryMetamethod = '__mod' | '__index' | '__newindex' | '__add' | '__mul' | '__sub';

export const ENTRY_METAMETHODS: EntryMetamethod[] = [
  '__mod',
  '__index',
  '__newindex',
  '__add',
  '__mul',
  '__sub',
];

/** The operator token each metamethod maps to, when used as an entry point. */
export const METAMETHOD_OPERATOR: Partial<Record<EntryMetamethod, string>> = {
  __mod: '%',
  __add: '+',
  __mul: '*',
  __sub: '-',
};

export function pickEntryMetamethod(rng: () => number): EntryMetamethod {
  const i = Math.floor(rng() * ENTRY_METAMETHODS.length);
  return ENTRY_METAMETHODS[i % ENTRY_METAMETHODS.length];
}

/* --------------------------------------------------------------------------
 * Luau emission
 * ------------------------------------------------------------------------*/

export interface MetamorphicEmitCtx {
  nm: (hint: string) => string;
  /** name of the raw handler table (op -> function) */
  nRaw: string;
  /** name of the merged mutation table (STEP 8) */
  nMutation: string;
  /** name of the VM runner / execution function */
  nRun: string;
  /** name of the closure factory */
  nMakeClosure: string;
}

/**
 * 1 + 2: the metamorphic dispatch table and the protos table.
 *
 * Returns the names it created so buildVMRuntime can wire them in.
 */
export function emitMetamorphicTablesLua(
  ctx: MetamorphicEmitCtx,
  entry: EntryMetamethod
): { nDispatch: string; nProtos: string; code: string } {
  const { nm, nRaw, nMutation, nRun } = ctx;
  const nDispatch = nm('H');
  const nProtos = nm('P');

  const lines: string[] = [];
  lines.push(`-- metamorphic dispatch (STEP 5)`);
  lines.push(
    `local ${nDispatch}=setmetatable({},{__index=function(_,k) return ${nRaw}[${nMutation}[k] or k] end})`
  );

  // protos table: several metamethods all route to the runner, the chosen
  // one is simply the one the emitted code actually uses
  const mms = ['__mod', '__add', '__mul', '__sub'];
  const bodies = mms.map(
    (mm) => `${mm}=function(a,b) return ${nRun}(b~=nil and b or a) end`
  );
  bodies.push(`__index=function(_,k) return ${nRun}(k) end`);
  bodies.push(`__newindex=function(t,k,v) ${nRun}(k) rawset(t,k,v) end`);
  lines.push(`local ${nProtos}=setmetatable({},{${bodies.join(',')}})`);
  lines.push(`-- entry metamethod for this build: ${entry}`);
  return { nDispatch, nProtos, code: lines.join('\n') };
}

/**
 * 3: the CLOSURE handler body.  Instead of calling the factory directly it
 * goes through the protos metamethod, so there is no direct call edge from
 * the dispatch loop into the closure factory.
 */
export function emitClosureViaMetamethodLua(
  ctx: MetamorphicEmitCtx,
  nProtos: string,
  entry: EntryMetamethod,
  nChunk: string
): string {
  const { nm } = ctx;
  const nIdx = nm('protoIndex');
  const op = METAMETHOD_OPERATOR[entry];

  if (op) {
    return [
      `local ${nIdx}=${nChunk}.protos and ${nChunk}.protos[B + 1] or B`,
      `R[A]=${nProtos} ${op} ${nIdx}   -- triggers ${entry}`,
    ].join('\n');
  }
  return [
    `local ${nIdx}=${nChunk}.protos and ${nChunk}.protos[B + 1] or B`,
    `R[A]=${nProtos}[${nIdx}]   -- triggers ${entry}`,
  ].join('\n');
}

/**
 * The arithmetic bridge: when either operand is a table, the arithmetic
 * handler routes through a metamethod instead of the native operator.
 */
export function emitArithmeticBridgeLua(
  ctx: MetamorphicEmitCtx,
  nProtos: string,
  operator: '+' | '-' | '*' | '/' | '%'
): string {
  const { nm, nRun } = ctx;
  const fn = nm('bridge');
  return [
    `local function ${fn}(a,b)`,
    ` if type(a)=='table' or type(b)=='table' then`,
    `  return ${nRun}(type(a)=='table' and b or a)`,
    ` end`,
    ` return a ${operator} b`,
    `end`,
    `-- handlers use ${fn}(R[B],R[C]) instead of R[B] ${operator} R[C]`,
    `-- so a table operand silently becomes a VM entry point`,
    `${nProtos}`,
  ].join('\n');
}

/**
 * Luraph docs: "__namecall not invoked by : calls, invokes __index instead".
 * We lean on that: method resolution goes through __index on the protos
 * table, which is also a VM entry point.
 */
export function emitNamecallBridgeLua(
  ctx: MetamorphicEmitCtx,
  nProtos: string
): string {
  const { nm } = ctx;
  const fn = nm('ncall');
  return [
    `-- namecall bridge: ':' calls resolve through __index, never __namecall`,
    `local function ${fn}(obj,key)`,
    ` local v=${nProtos}[key]`,
    ` if v~=nil then return v end`,
    ` local mt=getmetatable(obj)`,
    ` if mt and rawget(mt,'__index') then return rawget(mt,'__index')(obj,key) end`,
    ` return obj[key]`,
    `end`,
  ].join('\n');
}

/**
 * A second, hidden entry point used by the metamorphic layer.  Nothing in
 * the emitted source calls it by its own name - it is only ever reached
 * through a metamethod.
 */
export function emitHiddenEntryLua(
  ctx: MetamorphicEmitCtx,
  entry: EntryMetamethod
): string {
  const { nm, nRun } = ctx;
  const fn = nm('h');
  return [
    `local ${fn}`,
    `${fn}=function(x)`,
    ` -- reached only via ${entry}`,
    ` if x==nil then return nil end`,
    ` return ${nRun}(x)`,
    `end`,
  ].join('\n');
}

/** Sanity: the swap table must be an involution on tokens. */
export function roundTripOperandSwap(): boolean {
  const a = swapOperands('R[{A}]=RK({B})*RK({C})', 'BC');
  if (a !== 'R[{A}]=RK({C})*RK({B})') return false;
  const b = swapOperands(swapOperands('R[{A}]=RK({B})*RK({C})', 'BC'), 'BC');
  return b === 'R[{A}]=RK({B})*RK({C})';
}
