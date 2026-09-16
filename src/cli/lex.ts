#!/usr/bin/env node

import { readFileSync } from "fs";
import { lex } from "../lexer/Lexer.js";

const file = process.argv[2];
const source = file
  ? readFileSync(file, "utf-8")
  : `local x = 42
print("Hello " .. x)
-- comment
`;

const { tokens, errors } = lex(source);

if (errors.length > 0) {
  console.error("Errors:");
  for (const e of errors) {
    console.error(`  ${e.loc.start.line}:${e.loc.start.column}: ${e.message}`);
  }
}

console.log("Tokens:");
for (const t of tokens) {
  const val = "value" in t ? ` ${JSON.stringify((t as { value?: string }).value)}` : "";
  const raw = "raw" in t ? ` raw=${JSON.stringify((t as { raw?: string }).raw)}` : "";
  console.log(`  ${t.type}${val}${raw} @ ${t.loc.start.line}:${t.loc.start.column}`);
}
