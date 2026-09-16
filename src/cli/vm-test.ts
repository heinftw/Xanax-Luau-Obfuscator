#!/usr/bin/env node

import { readFileSync } from "fs";
import { join } from "path";
import { lex } from "../lexer/Lexer.js";
import { parse } from "../parser/Parser.js";
import { obfuscate } from "../obfuscator/Obfuscator.js";
import { compile } from "../vm/Compiler.js";
import { runVM } from "../vm/vm-runner.js";

const args = process.argv.slice(2);
const file = args[0] || join(process.cwd(), "test", "vm-simple-test.luau");

let source: string;
try {
  source = readFileSync(file, "utf-8");
} catch {
  source = `print("Hello")
local x = 1 + 2
print(x)
`;
}

console.log("=== VM-Test: Compile and Execute ===\n");
console.log("Source code:");
console.log(source);
console.log("\n---");

const { tokens, errors } = lex(source);
if (errors.length > 0) {
  console.error("Lexer errors:", errors);
  process.exit(1);
}

const ast = parse(tokens);
const obfuscated = obfuscate(ast, { renameLocals: true, preserveGlobals: true });
const chunk = compile(obfuscated);

console.log("\nK (Constants):", JSON.stringify(chunk.K, null, 2));
console.log("\nCode (first 50):", chunk.code.slice(0, 50).join(","));

const mockEnv: Record<string, unknown> = {
  print: (...a: unknown[]) => console.log("[VM]", ...a),
  warn: (...a: unknown[]) => console.warn("[VM warn]", ...a),
  error: (msg: unknown) => { throw new Error(String(msg)); },
  assert: (v: unknown, msg?: unknown) => { if (!v) throw new Error(msg ? String(msg) : "assertion failed"); return v; },
  type: (v: unknown) => {
    if (v === null || v === undefined) return "nil";
    if (typeof v === "function") return "function";
    if (typeof v === "object") return "table";
    return typeof v;
  },
  typeof: (v: unknown) => {
    if (v === null || v === undefined) return "nil";
    if (typeof v === "function") return "function";
    if (typeof v === "object") return "table";
    return typeof v;
  },
  tostring: (v: unknown) => v === null || v === undefined ? "nil" : String(v),
  tonumber: (v: unknown) => { const n = Number(v); return isNaN(n) ? null : n; },
  pcall: (f: Function, ...args: unknown[]) => {
    try { const r = f(...args); return Array.isArray(r) ? [true, ...r] : [true, r]; }
    catch (e) { return [false, e instanceof Error ? e.message : String(e)]; }
  },
  select: (idx: unknown, ...args: unknown[]) => {
    if (idx === "#") return args.length;
    const n = Number(idx);
    if (n >= 1 && n <= args.length) return args[n - 1];
    return null;
  },
  pairs: (t: Record<string, unknown>) => {
    const keys = Object.keys(t);
    let i = 0;
    return [(..._: unknown[]) => {
      if (i >= keys.length) return [null];
      const k = keys[i++];
      return [k, t[k]];
    }, t, null];
  },
  ipairs: (t: Record<number, unknown>) => {
    let i = 0;
    return [(..._: unknown[]) => {
      i++;
      const v = t[i];
      if (v === undefined || v === null) return [null];
      return [i, v];
    }, t, 0];
  },
  next: (t: Record<string, unknown>, k?: string) => {
    const keys = Object.keys(t);
    if (k === undefined || k === null) return keys.length > 0 ? [keys[0], t[keys[0]]] : [null];
    const idx = keys.indexOf(String(k));
    if (idx < 0 || idx + 1 >= keys.length) return [null];
    return [keys[idx + 1], t[keys[idx + 1]]];
  },
  rawget: (t: Record<string, unknown>, k: string) => t[k],
  rawset: (t: Record<string, unknown>, k: string, v: unknown) => { t[k] = v; return t; },
  rawequal: (a: unknown, b: unknown) => a === b,
  setmetatable: (t: unknown, _mt: unknown) => t,
  getmetatable: (_t: unknown) => null,
  string: {
    len: (s: string) => s.length,
    sub: (s: string, i: number, j?: number) => s.substring(i - 1, j),
    rep: (s: string, n: number) => s.repeat(n),
    byte: (s: string, i?: number) => s.charCodeAt((i || 1) - 1),
    char: (...codes: number[]) => String.fromCharCode(...codes),
    format: (fmt: string, ...args: unknown[]) => {
      let i = 0;
      return fmt.replace(/%[dfs%%]/g, (m) => {
        if (m === "%%") return "%";
        return String(args[i++] ?? "");
      });
    },
    find: (s: string, pattern: string) => { const idx = s.indexOf(pattern); return idx >= 0 ? [idx + 1, idx + pattern.length] : [null]; },
    lower: (s: string) => s.toLowerCase(),
    upper: (s: string) => s.toUpperCase(),
    reverse: (s: string) => s.split("").reverse().join(""),
    gsub: (s: string, pattern: string, repl: string) => [s.split(pattern).join(repl)],
    match: (s: string, _pattern: string) => [null],
  },
  table: {
    insert: (t: Record<number, unknown>, ...args: unknown[]) => {
      if (args.length === 1) {
        const keys = Object.keys(t).filter(k => !isNaN(Number(k))).map(Number);
        const len = keys.length > 0 ? Math.max(...keys) : 0;
        t[len + 1] = args[0];
      } else {
        t[args[0] as number] = args[1];
      }
    },
    remove: (t: Record<number, unknown>, pos?: number) => {
      const keys = Object.keys(t).filter(k => !isNaN(Number(k))).map(Number).sort((a,b) => a-b);
      const idx = pos || keys[keys.length - 1];
      const val = t[idx];
      delete t[idx];
      return val;
    },
    concat: (t: Record<number, unknown>, sep?: string) => {
      const keys = Object.keys(t).filter(k => !isNaN(Number(k))).map(Number).sort((a,b) => a-b);
      return keys.map(k => String(t[k])).join(sep || "");
    },
    sort: () => {},
    unpack: (t: Record<number, unknown>, i?: number, j?: number) => {
      const start = i || 1;
      const keys = Object.keys(t).filter(k => !isNaN(Number(k))).map(Number);
      const end = j || (keys.length > 0 ? Math.max(...keys) : 0);
      const results: unknown[] = [];
      for (let k = start; k <= end; k++) results.push(t[k]);
      return results;
    },
  },
  math: {
    max: (...a: number[]) => Math.max(...a),
    min: (...a: number[]) => Math.min(...a),
    floor: (n: number) => Math.floor(n),
    ceil: (n: number) => Math.ceil(n),
    abs: (n: number) => Math.abs(n),
    sqrt: (n: number) => Math.sqrt(n),
    sin: (n: number) => Math.sin(n),
    cos: (n: number) => Math.cos(n),
    random: (m?: number, n?: number) => {
      if (m === undefined) return Math.random();
      if (n === undefined) return Math.floor(Math.random() * m) + 1;
      return Math.floor(Math.random() * (n - m + 1)) + m;
    },
    huge: Infinity,
    pi: Math.PI,
  },
  bit32: {
    bxor: (...a: number[]) => a.reduce((acc, v) => acc ^ v, 0),
    band: (...a: number[]) => a.reduce((acc, v) => acc & v, 0xFFFFFFFF),
    bor: (...a: number[]) => a.reduce((acc, v) => acc | v, 0),
    bnot: (n: number) => ~n,
    lshift: (n: number, b: number) => n << b,
    rshift: (n: number, b: number) => n >>> b,
  },
  coroutine: {},
  os: { clock: () => Date.now() / 1000, time: () => Math.floor(Date.now() / 1000) },
  game: { HttpGet: () => "return {}" },
  workspace: {},
  script: {},
  loadstring: (code: string) => () => null,
  _G: {},
  shared: {},
  unpack: (t: Record<number, unknown>, i?: number, j?: number) => {
    const start = i || 1;
    const keys = Object.keys(t).filter(k => !isNaN(Number(k))).map(Number);
    const end = j || (keys.length > 0 ? Math.max(...keys) : 0);
    const results: unknown[] = [];
    for (let k = start; k <= end; k++) results.push(t[k]);
    return results;
  },
};

mockEnv._G = mockEnv;

console.log("\n--- Execution ---\n");

try {
  const result = runVM(chunk.K, chunk.code, mockEnv, 0, chunk.protos || []);
console.log("\nReturn value:", result);
console.log("\nVM test successful");
} catch (err) {
  console.error("\nVM error:", err);
  process.exit(1);
}
