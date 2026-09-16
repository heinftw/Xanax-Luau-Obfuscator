#!/usr/bin/env node

import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { lex } from "../lexer/Lexer.js";
import { parse } from "../parser/Parser.js";
import { obfuscate } from "../obfuscator/Obfuscator.js";
import { encodeStrings } from "../obfuscator/StringEncoder.js";
import { scrambleControlFlow } from "../obfuscator/ControlFlowScrambler.js";
import { printChunk, printChunkOneLine } from "../obfuscator/Printer.js";
import { compile } from "../vm/Compiler.js";
import { generateVM } from "../vm/vm-gen.js";
import type { VMGenLevel } from "../vm/vm-gen.js";

const args = process.argv.slice(2);
const noRename = args.includes("--no-rename");
const noPreserve = args.includes("--no-preserve");
const encodeStringsOpt = args.includes("--encode-strings");
const noEncode = args.includes("--no-encode");
const scrambleOpt = args.includes("--scramble");
const vmOpt = args.includes("--vm");
const junkOpt = args.includes("--junk");
const oneLineOpt = args.includes("--one-line");
const productionOpt = args.includes("--production");
const advancedOpt = args.includes("--advanced");
const maxOpt = args.includes("--max");
const compressOpt = args.includes("--compress");
const noCompressOpt = args.includes("--no-compress");
const outIndex = args.findIndex((a) => a === "-o" || a === "--output");
const outFile = outIndex >= 0 ? args[outIndex + 1] : null;
const fileArgs = args.filter((a, i) =>
  !a.startsWith("-") && (outIndex < 0 || i < outIndex || i > outIndex + 1)
);
const file = fileArgs[0];

const source = file
  ? readFileSync(file, "utf-8")
  : `local x = 42
local name = "World"
print("Hello " .. name)
function foo(a, b)
  return a + b
end
`;

const { tokens, errors } = lex(source);
if (errors.length > 0) {
  console.error("Lexer errors:", errors);
  process.exit(1);
}

let ast = parse(tokens);
if (encodeStringsOpt && !noEncode) {
  ast = encodeStrings(ast, { enabled: true });
}
if (scrambleOpt) {
  ast = scrambleControlFlow(ast, { enabled: true });
}
let output: string;
if (vmOpt) {
  const obfuscated = obfuscate(ast, {
    renameLocals: !noRename,
    preserveGlobals: !noPreserve,
  });
  const chunk = compile(obfuscated);
  const vmDebug = args.includes("--vm-debug");

  let level: VMGenLevel = "normal";
  if (vmDebug || args.includes("--no-vm-encode")) level = "debug";
  if (maxOpt || advancedOpt || productionOpt) level = "max";

  output = generateVM(chunk, { level, executorGlobals: level !== "debug", noCompression: noCompressOpt });
} else {
  const obfuscated = obfuscate(ast, {
    renameLocals: !noRename,
    preserveGlobals: !noPreserve,
  });
  output = printChunk(obfuscated);
}

if (outFile) {
  writeFileSync(outFile, output, "utf-8");
  console.error(`Obfuscated to ${outFile}`);
} else {
  console.log(output);
}
