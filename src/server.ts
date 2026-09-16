import express from "express";
import { exec } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

import { validate } from "./compiler/LuauCompiler.js";
import { lex } from "./lexer/Lexer.js";
import { parse } from "./parser/Parser.js";
import { obfuscate } from "./obfuscator/Obfuscator.js";
import { encodeStrings } from "./obfuscator/StringEncoder.js";
import { scrambleControlFlow } from "./obfuscator/ControlFlowScrambler.js";
import { printChunk, printChunkOneLine } from "./obfuscator/Printer.js";
import { compile } from "./vm/Compiler.js";
import { regCompile } from "./vm/RegCompiler.js";
import { generateVM } from "./vm/vm-gen.js";
import { generateRegVM } from "./vm/reg-vm-gen.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json());

app.use(express.static(join(__dirname, "..", "public")));

app.post("/api/validate", (req: express.Request, res: express.Response) => {
  try {
    const { code } = req.body;
    if (typeof code !== "string") {
      return res.status(400).json({ error: "Invalid 'code' parameter" }) as any;
    }
    console.log(`[API] /api/validate - Code length: ${code.length} characters`);
    const result = validate(code);
    res.json(result);
  } catch (err: any) {
    console.error("[API-ERROR] /api/validate failed:", err);
    res.status(500).json({ error: `Server error: ${err.message}` });
  }
});

app.post("/api/obfuscate", (req: express.Request, res: express.Response) => {
  try {
    const { code, options } = req.body;
    if (typeof code !== "string") {
      return res.status(400).json({ error: "Invalid 'code' parameter" }) as any;
    }

    const opts = options || {};
    const noRename = opts.noRename === true;
    const noPreserve = opts.noPreserve === true;
    const encodeStringsOpt = opts.encodeStrings === true;
    const scrambleOpt = opts.scramble === true;
    const oneLineOpt = opts.oneLine === true;
    const vmType = opts.vmType || "none";
    const vmLevel = opts.vmLevel || "normal";

    console.log(`[API] /api/obfuscate - VM: ${vmType}, Level: ${vmLevel}, length: ${code.length}`);

    const { tokens, errors: lexErrors } = lex(code);
    if (lexErrors.length > 0) {
      return res.status(400).json({ error: "Lexer error", details: lexErrors });
    }

    let ast = parse(tokens);

    if (encodeStringsOpt) {
      ast = encodeStrings(ast, { enabled: true });
    }

    if (scrambleOpt) {
      ast = scrambleControlFlow(ast, { enabled: true });
    }

    let output: string;

    if (vmType === "stack") {

      const obfuscated = obfuscate(ast, {
        renameLocals: !noRename,
        preserveGlobals: !noPreserve,
      });

      const chunk = compile(obfuscated);

      output = generateVM(chunk, {
        level: vmLevel as any,
        executorGlobals: vmLevel !== "debug",
      });
    } else if (vmType === "register") {

      const obfuscated = obfuscate(ast, {
        renameLocals: !noRename,
        preserveGlobals: !noPreserve,
      });

      const chunk = regCompile(obfuscated);

      const disableFeatures: string[] = [];
      if (vmLevel === "debug") disableFeatures.push("controlFlowFlattening");

      output = generateRegVM(chunk, {
        level: vmLevel as any,
        executorGlobals: vmLevel !== "debug",
        polymorphicSeed: Date.now(),
        disableFeatures: disableFeatures as any[],
      });
    } else {

      const obfuscated = obfuscate(ast, {
        renameLocals: !noRename,
        preserveGlobals: !noPreserve,
      });
      output = oneLineOpt ? printChunkOneLine(obfuscated) : printChunk(obfuscated);
    }

    if (oneLineOpt && vmType !== "none") {
      output = output
        .split("\n")
        .map(l => l.trim())
        .filter(l => l.length > 0 && !l.startsWith("--"))
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
    }

    res.json({ output });
  } catch (err: any) {
    console.error("Obfuscation error:", err);
    res.status(500).json({ error: `Server error: ${err.message}` });
  }
});

app.listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log(`\nXanax Obfuscator Server running at: ${url}`);
  console.log("Press CTRL+C to terminate.\n");

  exec(`start ${url}`, (err) => {
    if (err) {
      console.log(`Note: Failed to open browser automatically. Please navigate manually to ${url}`);
    } else {
      console.log(`Browser automatically opened at ${url}`);
    }
  });
});
