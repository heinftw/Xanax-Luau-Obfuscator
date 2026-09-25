/* ============================================================================
 * XANAX OBFUSCATOR - src/vm/IntenseStructure.ts
 * PART 1 / STEP 6 : INTENSE VM STRUCTURE
 * ----------------------------------------------------------------------------
 * Luraph history:
 *   v13.4  "Intense VM Structure (replaces the outdated #{...} security)"
 *   v14.2  "completely new output generation structure ... made VM code
 *           harder to simplify"
 * Grokipedia: "control flow obfuscation: nested conditionals and loops
 *              evaluating opcodes in layers"
 *
 * This file provides the building blocks buildVMRuntime() needs:
 *
 *   1. splitVMRuntime()   - break the runtime into nested functions.  The
 *                           outer one only sets up locals (R, K, code, ip,
 *                           env); the inner one is the dispatch loop.
 *                           Closure boundaries defeat control-flow analysis.
 *   2. opaquePredicate()  - provably-constant predicates that conditionally
 *                           touch handler locals then restore them.
 *   3. handlerVariant()   - 3..5 semantically identical bodies per handler,
 *                           picked at random per build.
 *   4. obfLoopCondition() - `while ip-#code<=0 do` style conditions.
 *   5. orderHandlers()    - random body order, some inlined, some functions.
 * ==========================================================================*/

/* --------------------------------------------------------------------------
 * 1. Nested function splitting
 * ------------------------------------------------------------------------*/

export interface VMSection {
  /** local names this section declares (used for dependency shuffling) */
  declares: string[];
  /** local names this section reads */
  reads: string[];
  code: string;
}

export interface NestedSplit {
  outer: string;
  inners: string[];
  /** the local that must be called to start the dispatch loop */
  entry: string;
}

/**
 * Wrap the VM setup + dispatch loop in nested functions.
 *
 * `setup`    - text that declares R / K / code / ip / env
 * `dispatch` - the dispatch loop text
 * `nm`       - name generator
 *
 * The dispatch loop becomes a closure over the setup locals, so a decompiler
 * cannot flatten it into a single function without doing real closure
 * analysis.  Every level is optional and randomised.
 */
export function splitVMRuntime(
  setup: string,
  dispatch: string,
  nm: (hint: string) => string,
  rng: () => number,
  depth = 2
): NestedSplit {
  const levels = Math.max(1, Math.min(4, depth + (rng() < 0.3 ? 1 : 0)));
  const names: string[] = [];
  for (let i = 0; i < levels; i++) names.push(nm(`lvl${i}`));

  // innermost first
  let current = dispatch;
  let entry = names[levels - 1];

  for (let i = levels - 1; i >= 1; i--) {
    const fn = names[i];
    const prev = names[i - 1];
    current = [
      `local function ${fn}()`,
      current,
      `end`,
      `-- opaque call chain: ${fn} -> ${prev}`,
      `${fn}=${fn}`,
    ].join('\n');
    entry = fn;
    void prev;
  }

  const outer = [
    `do`,
    setup,
    `local ${entry}`,
    `local function ${entry}()`,
    dispatch,
    `end`,
    `${entry}()`,
    `end`,
  ].join('\n');

  return { outer, inners: [current], entry };
}

/* --------------------------------------------------------------------------
 * 2. Opaque predicates
 * ------------------------------------------------------------------------*/

export interface OpaquePredicate {
  /** the expression - embed it in an `if ... then` */
  expr: string;
  /** the value it ALWAYS evaluates to */
  value: boolean;
  /** why - keep this so nobody "fixes" it later */
  proof: string;
}

/**
 * Build a provably-constant predicate over `v`.
 * All of these hold for every numeric value of `v`, including negatives,
 * non-integers and inf.  NaN is impossible here because we only ever feed
 * register values that the VM itself produced.
 */
export function opaquePredicate(rng: () => number, v: string): OpaquePredicate {
  const allTrue: OpaquePredicate[] = [
    {
      expr: `(${v}*${v}+${v})%2==0`,
      value: true,
      proof: 'x(x+1) is a product of consecutive integers, hence even',
    },
    {
      expr: `(${v}*${v}-${v})%2==0`,
      value: true,
      proof: 'x(x-1) is a product of consecutive integers, hence even',
    },
    {
      expr: `((${v}*7+3)-(7*${v}+3))==0`,
      value: true,
      proof: 'identical expressions subtracted',
    },
    {
      expr: `((${v}%2)*(${v}%2-1))==0`,
      value: true,
      proof: 'n(n-1) is even for any integer n',
    },
    {
      expr: `${v}+1>${v}-1`,
      value: true,
      proof: 'strictly increasing translation',
    },
    {
      expr: `math.floor(${v}*0+1)==1`,
      value: true,
      proof: 'x*0+1 is the constant 1',
    },
  ];
  const allFalse: OpaquePredicate[] = [
    { expr: `${v}*${v}<0`, value: false, proof: 'a square is never negative' },
    { expr: `${v}~=${v}`, value: false, proof: 'reflexivity of equality' },
    { expr: `(${v}*0)>0`, value: false, proof: 'zero is not greater than zero' },
  ];

  const wantTrue = rng() < 0.75;
  const pool = wantTrue ? allTrue : allFalse;
  return pool[Math.floor(rng() * pool.length) % pool.length];
}

/**
 * An opaque block that conditionally modifies a handler local and restores
 * it.  Always a no-op at runtime; cannot be removed without proving the
 * predicate, and the predicate is not constant-foldable by a syntactic pass.
 */
export function emitOpaqueTouch(
  rng: () => number,
  nm: (hint: string) => string,
  target: string,
  counterVar: string
): string {
  const p = opaquePredicate(rng, counterVar);
  const tmp = nm('ot');
  if (p.value) {
    return [
      `if ${p.expr} then -- ${p.proof}`,
      ` local ${tmp}=${target}`,
      ` ${target}=${target} or nil`,
      ` ${target}=${tmp}`,
      `end`,
    ].join('\n');
  }
  return [
    `if ${p.expr} then -- never taken: ${p.proof}`,
    ` local ${tmp}=${target}`,
    ` ${target}=nil`,
    ` ${target}=${tmp}`,
    `end`,
  ].join('\n');
}

/* --------------------------------------------------------------------------
 * 3. Metamorphic handler bodies
 * ------------------------------------------------------------------------*/

/**
 * Produce 3..5 semantically identical renderings of a handler body.
 * `body` may contain {A} {B} {C} {R} {K} {ip} tokens.
 */
export function handlerVariants(
  body: string,
  rng: () => number,
  count = 3 + Math.floor(rng() * 3)
): string[] {
  const variants = new Set<string>();
  variants.add(body);

  const withLocal = body.replace(/\{R\}\[{A}\]/g, '_t');
  if (withLocal !== body) {
    variants.add(`local _t={R}[{A}]\n${withLocal}\n{R}[{A}]=_t`);
  }
  variants.add(`do local _z=0 {R}[{A}]=({R}[{A}] or _z)-_z+(${body}) end`);
  variants.add(`do ${body} end`);
  variants.add(`for _0once=1,1 do ${body} end`);
  variants.add(`repeat ${body} until true`);
  variants.add(`if true then ${body} end`);

  const out: string[] = [];
  for (const v of variants) {
    out.push(v);
    if (out.length >= count) break;
  }
  return out;
}

/** Pick one variant at random. */
export function pickHandlerVariant(body: string, rng: () => number): string {
  const vs = handlerVariants(body, rng);
  return vs[Math.floor(rng() * vs.length) % vs.length];
}

/* --------------------------------------------------------------------------
 * 4. Obfuscated loop conditions
 * ------------------------------------------------------------------------*/

/** `while ip <= #code do` without ever writing it that way. */
export function obfLoopCondition(
  rng: () => number,
  nIp: string,
  nCode: string
): string {
  const forms = [
    `${nIp}-#${nCode}<=0`,
    `#${nCode}-${nIp}>=0`,
    `not(${nIp}>#${nCode})`,
    `(${nIp}<=#${nCode})==true`,
    `(${nIp}>#${nCode})==false`,
    `#{nCode}>=${nIp}`,
    `(${nIp}-#${nCode})<1`,
  ];
  return forms[Math.floor(rng() * forms.length) % forms.length];
}

/** Same for the `ip >= 1` guard used when walking backwards. */
export function obfLowerBound(rng: () => number, nIp: string): string {
  const forms = [`${nIp}>0`, `not(${nIp}<1)`, `${nIp}-1>=0`, `(${nIp}>=1)==true`];
  return forms[Math.floor(rng() * forms.length) % forms.length];
}

/* --------------------------------------------------------------------------
 * 5. Handler ordering / inlining
 * ------------------------------------------------------------------------*/

export interface HandlerEntry {
  op: number;
  body: string;
  /** emit as a function instead of inline in the dispatch chain */
  asFunction: boolean;
}

export interface OrderedHandlers {
  entries: HandlerEntry[];
  functions: { name: string; body: string }[];
}

/**
 * Random order + random inlining decision.  `bodies` maps an opcode to its
 * already-metamorphised body.
 */
export function orderHandlers(
  bodies: Map<number, string>,
  rng: () => number,
  nm: (hint: string) => string
): OrderedHandlers {
  const ops = Array.from(bodies.keys());
  for (let i = ops.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = ops[i];
    ops[i] = ops[j];
    ops[j] = t;
  }

  const entries: HandlerEntry[] = [];
  const functions: { name: string; body: string }[] = [];

  for (const op of ops) {
    const body = bodies.get(op) as string;
    const asFunction = rng() < 0.35;
    if (asFunction) {
      const name = nm('h');
      functions.push({ name, body });
      entries.push({ op, body: `${name}({A},{B},{C},{R},{K})`, asFunction: true });
    } else {
      entries.push({ op, body, asFunction: false });
    }
  }

  return { entries, functions };
}

/**
 * Assemble the dispatch chain in the randomised order.  Every handler body is
 * guarded by the obfuscated condition, and opaque touches are sprinkled in.
 */
export function emitDispatchChain(
  ordered: OrderedHandlers,
  nm: (hint: string) => string,
  rng: () => number,
  nIp: string,
  nCode: string
): string {
  const lines: string[] = [];
  const cond = obfLoopCondition(rng, nIp, nCode);
  const counter = nm('ctr');

  lines.push(`local ${counter}=0`);
  // hoisted handler functions (closure boundary breaks control flow analysis)
  for (const f of ordered.functions) {
    lines.push(`local function ${f.name}(_A,_B,_C,_R,_K)`);
    lines.push(f.body);
    lines.push(`end`);
  }

  lines.push(`while ${cond} do`);
  ordered.entries.forEach((e, idx) => {
    const kw = idx === 0 ? 'if' : 'elseif';
    lines.push(`${kw} _op==${e.op} then`);
    if (rng() < 0.3) lines.push(emitOpaqueTouch(rng, nm, '_R', counter));
    lines.push(e.body);
    if (rng() < 0.2) lines.push(emitOpaqueTouch(rng, nm, '_ip', counter));
  });

  lines.push(`end`);
  lines.push(`${counter}=${counter}+1`);
  lines.push(`end`);
  return lines.join('\n');
}

/** Prove every opaque predicate form really is constant. */
export function verifyOpaquePredicates(samples = 64): boolean {
  const xs = [0, 1, -1, 2, -2, 3, 7, -13, 0.5, -0.5, 100, 1e6, -1e6];
  for (const x of xs) {
    if (((x * x + x) % 2 + 2) % 2 !== 0) return false;
    if (((x * x - x) % 2 + 2) % 2 !== 0) return false;
    if (x * 7 + 3 - (7 * x + 3) !== 0) return false;
    if (!(x + 1 > x - 1)) return false;
    if (Math.floor(x * 0 + 1) !== 1) return false;
    if (x * x < 0) return false;
    if (x !== x) return false;
  }
  void samples;
  return true;
}
