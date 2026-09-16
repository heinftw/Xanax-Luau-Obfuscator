#!/usr/bin/env node

import { readFileSync } from "fs";
import { lex } from "../lexer/Lexer.js";
import { parse } from "../parser/Parser.js";

const args = process.argv.slice(2);
const validateOnly = args.includes("--validate");
const file = args.find((a) => !a.startsWith("-"));

const source = file
  ? readFileSync(file, "utf-8")
  : `local x = 42
print("Hello " .. x)
function foo(a, b)
  return a + b
end
`;

const { tokens, errors } = lex(source);
if (errors.length > 0) {
  console.error("Lexer errors:", errors);
  process.exit(1);
}

const ast = parse(tokens);

if (validateOnly) {
  console.log("OK - Parse successful");
} else {
  console.log(JSON.stringify(ast, null, 2));
}
