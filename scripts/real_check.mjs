#!/usr/bin/env node
// ============================================================================
// real_check — end-to-end verification for the Xanax register VM pipeline.
//
// For every fixture program:
//   1. run the original Luau source on a real Lua 5.4 VM (wasmoon)  -> reference
//   2. run it through lex > parse > obfuscate > regCompile > generateRegVM
//   3. execute the obfuscated VM output on a fresh Lua 5.4 VM       -> actual
//   4. compare printed output, byte for byte
//
// Also asserts VM-generator invariants:
//   - per-function opcode isolation: every proto carries its own decode table
//     and different protos get different alphabets
//   - determinism: same polymorphic seed -> identical output
//   - seed variation: different seed -> different output
//
// Usage (run "npm run build" first):
//   npm run real-check          # full matrix
//   npm run real-check-quick    # reduced matrix
//
// Environment:
//   NO_SEC=1 is forced while generating (skips Roblox-only anti-tamper env
//   checks so output can run outside Roblox).
// ============================================================================

import { LuaFactory } from "wasmoon";
import { lex } from "../dist/lexer/Lexer.js";
import { parse } from "../dist/parser/Parser.js";
import { obfuscate } from "../dist/obfuscator/Obfuscator.js";
import { regCompile } from "../dist/vm/RegCompiler.js";
import { generateRegVM } from "../dist/vm/reg-vm-gen.js";

const QUICK = process.argv.includes("--quick");

// Shims so Luau-targeted output runs on plain Lua 5.4 (wasmoon).
const LUA_PRELUDE = `
__bit32_bw = function(a, op, init, ...)
  a = math.floor(a) & 0xFFFFFFFF
  local r = init
  for i = 1, select('#', ...) do
    local b = math.floor((select(i, ...))) & 0xFFFFFFFF
    r = op(r, b)
  end
  return r & 0xFFFFFFFF
end
bit32 = bit32 or {}
bit32.band = function(a, ...) return __bit32_bw(a, function(x, y) return x & y end, a, ...) end
bit32.bor  = function(a, ...) return __bit32_bw(a, function(x, y) return x | y end, a, ...) end
bit32.bxor = function(a, ...) return __bit32_bw(a, function(x, y) return x ~ y end, a, ...) end
bit32.bnot = function(a) return (~math.floor(a)) & 0xFFFFFFFF end
bit32.lshift = function(a, b) return (math.floor(a) << math.floor(b)) & 0xFFFFFFFF end
bit32.rshift = function(a, b) return (math.floor(a) >> math.floor(b)) & 0xFFFFFFFF end
bit32.arshift = bit32.rshift
table.create = table.create or function(n, v)
  local t = {}
  if v ~= nil then for i = 1, n do t[i] = v end end
  return t
end
loadstring = loadstring or function(s, chunkname) return load(s, chunkname or "=(loadstring)") end
__OUT = {}
print = function(...)
  local n = select('#', ...)
  local p = {}
  for i = 1, n do p[i] = tostring((select(i, ...))) end
  __OUT[#__OUT + 1] = table.concat(p, "\\t")
end
warn = print
`;

// ---------------------------------------------------------------------------
// Fixtures: plain-Lua-syntax Luau programs exercising the register VM opcode
// surface (closures, upvalues, varargs, loops, tables, pcall, namecall...).
// ---------------------------------------------------------------------------

const FIXTURES = [
  {
    name: "basic-arith-strings",
    src: `
print("Hello", 1 + 2 * 3)
print(10 - 4 / 2, 7 % 3, 2 ^ 8)
print(math.floor(17 / 5), -(-5))
local s = "abc" .. "def" .. tostring(42)
print(s, #s, string.upper(s), ("x"):rep(3))
`,
  },
  {
    name: "closures-counters",
    src: `
local function makeCounter(start)
  local count = start
  return function()
    count = count + 1
    return count
  end
end
local c1 = makeCounter(10)
local c2 = makeCounter(100)
print(c1(), c1(), c2(), c1())
local function outer()
  local x = 1
  local function mid()
    local function inner()
      x = x + 5
      return x
    end
    return inner
  end
  return mid()
end
print(outer()(), outer()())
`,
  },
  {
    name: "varargs-multiRet",
    src: `
local function sum(...)
  local s = 0
  for i = 1, select('#', ...) do s = s + select(i, ...) end
  return s, "done"
end
print(sum(1, 2, 3))
local a, b = sum(4, 5)
print(a, b)
local function va(n, ...)
  if n == 0 then return ... end
  return va(n - 1, ...)
end
print(va(3, "a", "b"))
local function pass() return 1, 2, 3 end
print(pass())
print((pass()))
local t = {pass()}
print(#t)
`,
  },
  {
    name: "loops-break",
    src: `
local acc = {}
for i = 1, 10 do
  if i % 2 == 0 then acc[#acc + 1] = i * i end
end
print(table.concat(acc, ","))
local n = 0
while true do
  n = n + 1
  if n >= 5 then break end
end
print(n)
local r = 0
repeat r = r + 3 until r > 7
print(r)
for i = 10, 1, -2 do acc[#acc + 1] = i end
print(table.concat(acc, " "))
`,
  },
  {
    name: "tables-ipairs-sort",
    src: `
local t = {3, 1, 4, 1, 5, 9, 2, 6}
table.sort(t)
local s = 0
for i, v in ipairs(t) do s = s + v * i end
print(s, #t, t[1], t[#t])
local keys = 0
local dict = {alpha = 1, beta = 2}
dict.gamma = 3
for k, v in pairs(dict) do keys = keys + v end
print(keys, dict.alpha + dict.beta + dict.gamma)
local grid = {}
for i = 1, 3 do
  grid[i] = {}
  for j = 1, 3 do grid[i][j] = i * j end
end
print(grid[2][3], grid[3][3])
`,
  },
  {
    name: "pcall-error",
    src: `
local ok, err = pcall(function() error("boom", 0) end)
print(ok, err)
local ok2, v = pcall(function() return 7 end)
print(ok2, v)
print(pcall(function(a, b) return a + b end, 3, 4))
local function mayThrow(x)
  if x then error("bad", 0) end
  return "fine"
end
print(pcall(mayThrow, true))
print(pcall(mayThrow, false))
local okx, ex = xpcall(function() error("xp", 0) end, function(m) return "handled:" .. m end)
print(okx, ex)
`,
  },
  {
    name: "recursion-fib",
    src: `
local function fib(n)
  if n < 2 then return n end
  return fib(n - 1) + fib(n - 2)
end
print(fib(15))
local function gcd(a, b)
  if b == 0 then return a end
  return gcd(b, a % b)
end
print(gcd(1071, 462))
local function deep(n)
  if n == 0 then return 0 end
  return 1 + deep(n - 1)
end
print(deep(200))
`,
  },
  {
    name: "closures-in-loops",
    src: `
local fns = {}
for i = 1, 5 do
  fns[i] = function() return i * 2 end
end
print(fns[1](), fns[3](), fns[5]())
local getters = {}
do
  local secret = 99
  getters.get = function() return secret end
  getters.set = function(v) secret = v end
end
print(getters.get())
getters.set(-1)
print(getters.get())
local acc2 = {}
for _, w in ipairs({"a", "b", "c"}) do
  acc2[#acc2 + 1] = function() return w .. "!" end
end
print(acc2[1](), acc2[3]())
`,
  },
  {
    name: "methods-self",
    src: `
local obj = {n = 0}
function obj:add(k)
  self.n = self.n + k
  return self.n
end
print(obj:add(5), obj:add(7))
function obj:describe()
  return "n=" .. tostring(self.n)
end
print(obj:describe())
local mt = {
  __index = function(t, k) return "idx:" .. k end,
  __add = function(a, b) return "added" end,
}
local proxy = setmetatable({}, mt)
print(proxy.whatever, proxy + 1)
`,
  },
  {
    name: "mixed-stress",
    src: `
local function compose(...)
  local fns = {...}
  return function(x)
    for i = #fns, 1, -1 do
      x = fns[i](x)
    end
    return x
  end
end
local inc = function(x) return x + 1 end
local dbl = function(x) return x * 2 end
local f = compose(inc, dbl, inc)
print(f(3), f(10))
local memo = {}
local function slow(n)
  if n <= 1 then return n end
  if memo[n] then return memo[n] end
  local r = slow(n - 1) + slow(n - 2)
  memo[n] = r
  return r
end
print(slow(30))
local co = 0
local function tick() co = co + 1 return co end
local handlers = {tick, tick, tick}
print(handlers[1](), handlers[3](), #handlers)
print(select(2, string.find("hello world", "w(%w+)")))
`,
  },
];

// ---------------------------------------------------------------------------
// Lua execution helpers
// ---------------------------------------------------------------------------

async function makeEngine() {
  const factory = new LuaFactory();
  const engine = await factory.createEngine();
  await engine.doString(LUA_PRELUDE);
  return engine;
}

async function runLua(source) {
  const engine = await makeEngine();
  try {
    await engine.doString(source);
    return await engine.doString('return table.concat(__OUT, "\\n")');
  } finally {
    engine.global.close();
  }
}

// ---------------------------------------------------------------------------
// Obfuscation pipeline
// ---------------------------------------------------------------------------

function obfuscateToVM(source, { level, seed, disableFeatures = [], noCipher = false }) {
  const prevNoSec = process.env.NO_SEC;
  const prevNoCipher = process.env.NO_CIPHER;
  process.env.NO_SEC = "1";
  if (noCipher) process.env.NO_CIPHER = "1";
  try {
    const { tokens, errors: lexErrors } = lex(source);
    if (lexErrors.length > 0) throw new Error("lex: " + lexErrors.map(e => e.message).join("; "));
    const ast = parse(tokens);
    const transformed = obfuscate(ast, { renameLocals: true, preserveGlobals: true });
    const chunk = regCompile(transformed);
    const out = generateRegVM(chunk, {
      level,
      executorGlobals: level !== "debug",
      polymorphicSeed: seed,
      debugTrace: false,
      disableFeatures,
    });
    return { out, protoCount: countProtos(chunk) };
  } finally {
    if (prevNoSec === undefined) delete process.env.NO_SEC; else process.env.NO_SEC = prevNoSec;
    if (prevNoCipher === undefined) delete process.env.NO_CIPHER; else process.env.NO_CIPHER = prevNoCipher;
  }
}

function countProtos(chunk) {
  let n = 1;
  for (const p of chunk.protos ?? []) n += countProtos(p);
  return n;
}

// ---------------------------------------------------------------------------
// Invariant checks on the generated output
// ---------------------------------------------------------------------------

// Every proto tuple must end with an 8th field: its own decode table.
function checkPerProtoIsolation(output, protoCount, label, failures) {
  // At obfuscated levels every proto object literal ends with a `[0]=`-pinned
  // byte table. Count them and require >= protoCount-1 (the root's table is
  // emitted separately as its own data var, adding one more match).
  const decTables = [...output.matchAll(/\[0\]=\d+(?:,\d+){56}\}/g)];
  if (decTables.length < protoCount - 1) {
    failures.push(`${label}: expected >= ${protoCount - 1} per-proto decode tables, found ${decTables.length}`);
    return;
  }
  // Distinctness: subkeys mix seed + tree index + depth, so identical
  // permutations across functions are astronomically unlikely. Require at
  // least 90% unique when the program has several protos.
  const uniq = new Set(decTables.map(m => m[0]));
  if (decTables.length >= 3 && uniq.size < Math.ceil(decTables.length * 0.9)) {
    failures.push(`${label}: per-proto decode alphabets not distinct (only ${uniq.size}/${decTables.length} unique)`);
  }
  // None of the alphabets may be the plain identity permutation — that would
  // defeat the whole point of per-function opcode isolation.
  for (const m of decTables) {
    const body = m[0].replace("[0]=", "").split(",").map(Number);
    if (body.every((v, i) => v === i)) {
      failures.push(`${label}: a proto decode table is the identity permutation`);
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Main matrix
// ---------------------------------------------------------------------------

const SEEDS = QUICK ? [1234] : [1234, 0xC0FFEE, 777];

const LEVELS = QUICK
  ? [["debug", false], ["max", true]]
  : [["debug", false], ["normal", true], ["max", true]];

const FEATURE_VARIANTS = [
  { tag: "default", disableFeatures: [] },
  { tag: "no-shuffle", disableFeatures: ["opcodeShuffle"] },
  { tag: "no-fusion", disableFeatures: ["opcodeFusion"] },
  { tag: "no-cff", disableFeatures: ["controlFlowFlattening"] },
];

async function main() {
  const failures = [];
  const stats = { cases: 0, fullCipher: 0 };
  const t0 = Date.now();

  // Reference outputs once per fixture.
  const references = [];
  for (const fx of FIXTURES) {
    try {
      references.push(await runLua(fx.src));
    } catch (e) {
      failures.push(`REFERENCE FAILED for ${fx.name}: ${e.message}`);
      references.push(null);
    }
  }

  for (let fi = 0; fi < FIXTURES.length; fi++) {
    const fx = FIXTURES[fi];
    const expected = references[fi];
    if (expected === null) continue;

    // Protos in this fixture (compile once with a throwaway run).
    const { protoCount } = obfuscateToVM(fx.src, { level: "debug", seed: 1 });

    for (const [level, noCipher] of LEVELS) {
      // Feature variants only on a subset of fixtures (keeps runtime sane).
      const variants = QUICK || fi % 3 === 0 ? FEATURE_VARIANTS : [FEATURE_VARIANTS[0]];
      for (const variant of variants) {
        for (const seed of SEEDS) {
          const label = `${fx.name} [${level}/${variant.tag}/seed=${seed}]`;
          stats.cases++;
          try {
            const { out } = obfuscateToVM(fx.src, { level, seed, disableFeatures: variant.disableFeatures, noCipher });

            // Generator invariants (shuffle on => isolation must hold).
            if (!variant.disableFeatures.includes("opcodeShuffle") && level !== "debug") {
              checkPerProtoIsolation(out, protoCount, label, failures);
            }

            // Determinism.
            if (seed === SEEDS[0] && !QUICK) {
              const { out: out2 } = obfuscateToVM(fx.src, { level, seed, disableFeatures: variant.disableFeatures, noCipher });
              if (out2 !== out) failures.push(`${label}: nondeterministic output for same seed`);
            }

            const actual = await runLua(out);
            if (actual !== expected) {
              failures.push(`${label}: OUTPUT MISMATCH\n--- expected ---\n${expected}\n--- actual ---\n${actual}`);
            }
          } catch (e) {
            failures.push(`${label}: EXCEPTION ${e.message}`);
          }
        }
      }
    }
  }

  // Full-cipher end-to-end (blob + bootstrap + LZMA path), max level.
  if (!QUICK) {
    for (const fx of [FIXTURES[1], FIXTURES[7]]) {
      const label = `${fx.name} [max/full-cipher]`;
      stats.fullCipher++;
      try {
        const expected = await runLua(fx.src);
        const { out } = obfuscateToVM(fx.src, { level: "max", seed: 31337, noCipher: false });
        const actual = await runLua(out);
        if (actual !== expected) {
          failures.push(`${label}: OUTPUT MISMATCH\n--- expected ---\n${expected}\n--- actual ---\n${actual}`);
        }
      } catch (e) {
        failures.push(`${label}: EXCEPTION ${e.message}`);
      }
    }
  }

  // Seed sensitivity: per-proto alphabets must change with the master seed.
  {
    const fx = FIXTURES[0];
    const tablesBySeed = {};
    for (const seed of [424242, 424243]) {
      const { out } = obfuscateToVM(fx.src, { level: "normal", seed });
      const decTables = [...out.matchAll(/\[0\]=\d+(?:,\d+){56}\}/g)].map(m => m[0]);
      tablesBySeed[seed] = new Set(decTables);
    }
    const [a, b] = Object.values(tablesBySeed);
    let overlap = 0;
    for (const t of a) if (b.has(t)) overlap++;
    if (overlap > 0) {
      failures.push(`seed sensitivity: ${overlap} decode alphabets shared across seeds (expected 0)`);
    }
  }

  const dt = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`\n=== real_check: ${stats.cases} cases (+${stats.fullCipher} full-cipher) in ${dt}s ===`);
  if (failures.length > 0) {
    console.log(`FAILED (${failures.length}):`);
    for (const f of failures) console.log("\n" + f);
    process.exit(1);
  }
  console.log("ALL CHECKS PASSED");
}

main().catch(e => {
  console.error("fatal:", e);
  process.exit(1);
});
