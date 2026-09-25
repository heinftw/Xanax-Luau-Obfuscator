# Xanax Obfuscator — Part 1 VM Upgrades

Ten drop-in modules for `src/vm/`. Nothing here rewrites `reg-vm-gen.ts`
(154 KB) — instead each step ships as a self-contained module plus the exact
function you have to touch. **Function names only, never line numbers**,
because every edit shifts the file.

## Files added

| file | step | what it does |
|---|---|---|
| `bytecode.ts` | 1, 7 | **replacement** for the stock file. Adds per-proto identity + per-proto opcode tables and the documented deviation contract (MUL `B/C` swap, `EQ/LT/LE` inverted `A`, absolute `JMP`, `FORPREP/FORLOOP` limit/step swap) |
| `ProtoKeygen.ts` | 1 | per-function opcode isolation, subkey = `master + treeIndex + depth` |
| `DeserCompiler.ts` | 2 | the Stage-1 deserialization VM compiler + Luau interpreter emitter |
| `InstrCipher.ts` | 3, 9 | 4-field rolling-chain encryption, `ar()` layout rotation, per-argument keys derived from the decrypted opcode, separate constant cipher |
| `SilentGuard.ts` | 4 | CBC-MAC, branchless register poisoning, zeroisation |
| `Metamorphic.ts` | 5 | `__mod`/`__index`/arithmetic metamethod dispatch, operand-swap registry |
| `IntenseStructure.ts` | 6 | nested-function splitting, opaque predicates, metamorphic handler bodies, obfuscated loop conditions |
| `MutationTable.ts` | 8 | 256-entry involutory runtime opcode mutation table |
| `lzss.ts` | 10 | LZSS compressor + emitted Luau inflate |
| `BootstrapFragments.ts` | 10 | fragment-graph bootstrap generator, replaces `generateBootstrap` |

---

## STEP 1 — per-function opcode isolation

`reg-vm-gen.ts` → `serializeRegProtos`

* Replace the single `shuffleOpcodes()` call with
  `buildProtoOpcodeMaps(root, masterSeed)`.
* Replace the body of `mapRegChunk()` with `mapRegChunkIsolated(chunk, chunk.opEncode)`.
* Emit the tables with `emitProtoDecodeTables(refs, nm, rng)`.
* In `buildVMRuntime`, replace the shared decode-table local with
  `emitDispatchDecodeHook(nm, nProtoTables, nDecodeTable)`.
* In the `CLOSURE` handler use `emitClosureUpvalueCapture(...)`.
* Entry point: `emitEntrypointDecode(nProtoTables, entryUid, nDecodeTable)`.
* Check: `assertUniqueTables(refs)` must be true for any input with >1 proto.

## STEP 2 — deserialization VM layer

* New file `DeserCompiler.ts` (already included).
* `reg-vm-gen.ts` → output assembly after blob encryption:
  the Speck32-decrypted blob is now **deserialization data**, not Real VM code.
* Build it with `compileDeserProgram(...)`, emit the interpreter with
  `emitDeserInterpreterLua(...)`, its decode table with
  `emitDeserDecodeTableLua(...)`, and the data with `emitDeserDataLua(...)`.
* The Real VM consumes the output table:
  `constants, decrypted_constants, Insts, REG_A, REG_B, REG_C, prototypes, upvalues, entrypoint`.
* Pass `nMacFn` to `emitDeserInterpreterLua` so anti-tamper runs *during*
  reconstruction.
* After the handoff call `emitDropDeserLua([...])` so Stage 1 becomes garbage.
* Check: `runDeserProgram(prog)` must reproduce the expected regions.

## STEP 3 — multi-layer instruction encryption

`reg-vm-gen.ts` → `serializeRegCode`, `buildVMRuntime`

* Body of `serializeRegCode` becomes `encryptRegCode(chunk, key, sink)`.
* Key from `deriveChainKey(seed)`; state from `initChainState(key)`.
* Replace the opcode-only decrypt loop in `buildVMRuntime` with
  `emitDecryptSectionLua(ctx)` — it decrypts **all four** fields.
* Constants: `encryptConstantTable(K, seed)` +
  `emitConstantDecryptLua(...)` → `decrypted_constants`.
* Check: `roundTripInstruction(seed)` and `roundTripConstants(seed)`.

## STEP 4 — silent register poisoning

`bootstrap-template.ts` → `nEnvInteg`, `nAntiDbg`, `mutate`;
`reg-vm-gen.ts` → `buildVMRuntime` dispatch loop

* `cbMac(words)` over the first 32 words of the deserialized `Insts`.
* `emitMacFunctionLua(ctx)` → innocuously named MAC helper.
* Paste `emitSilentPoisonLua(ctx, macFn, c1, c2)` **inside** the dispatch
  loop, right after `chain` decodes the opcode.
* Replace every `if not <integrity>() then mutate() end` with
  `emitSilentIntegrityLua(ctx, [...])`.
* At the end of the exec state call `emitZeroizeLua(nm, tables, scalars)`.
* Check: `roundTripMac()`, `poisonValue(true) === 0 && poisonValue(false) === 0xFF`.

## STEP 5 — metamorphic dispatch

`reg-vm-gen.ts` → `buildVMRuntime`, protos table setup

* `pickEntryMetamethod(rng)` per build.
* `emitMetamorphicTablesLua(ctx, entry)` → dispatch table whose `__index`
  applies the decode transformation, plus the protos table with `__mod`.
* `CLOSURE` handler: `emitClosureViaMetamethodLua(...)`.
* Arithmetic handlers: `emitArithmeticBridgeLua(ctx, nProtos, '+')` etc.
* Namecall: `emitNamecallBridgeLua(...)` (`:` calls resolve through `__index`,
  never `__namecall`).
* Check: `roundTripOperandSwap()`.

## STEP 6 — intense VM structure

`reg-vm-gen.ts` → `buildVMRuntime`

* `splitVMRuntime(setup, dispatch, nm, rng, 2)` — outer function only sets up
  `R, K, code, ip, env`; the inner one is the dispatch loop.
* Sprinkle `emitOpaqueTouch(rng, nm, target, counter)` inside handler bodies.
* `pickHandlerVariant(body, rng)` for 3–5 equivalent bodies per handler.
* `obfLoopCondition(rng, nIp, nCode)` → e.g. `while ip-#code<=0 do`.
* `orderHandlers(bodies, rng, nm)` + `emitDispatchChain(...)`.
* Check: `verifyOpaquePredicates()`.

## STEP 7 — opcode swap anti-convention

`bytecode.ts` is the single source of truth: `REG_DEVIATIONS`.
`RegCompiler.ts` and the handlers in `reg-vm-gen.ts` must both honour it.

* Call `applyRegDeviations(chunk)` once the chunk is finished.
* Call `absolutiseJumps(chunk)` after that (relative → absolute `A|B<<8`).
* Read FOR* slots through `mapForSlot()`, not `A+1` / `A+2`.
* Read compare flags through `invertCompareA()`.
* Check: `verifyDeviationRoundtrip(chunk)`; eyeball with `describeDeviations(chunk)`.

## STEP 8 — opcode mutation table

`reg-vm-gen.ts` → `buildVMRuntime`, after opcode decryption

* `buildMutationTable(rng, 0.28)` → `emitMutationTableLua(ctx, mt, rng, 4, chainSeed)`.
* In the dispatch loop, immediately after the opcode is decrypted:
  `emitMutationApplyLua(nTable, nOp)`.
* Check: `assertInvolutory(mt.table)` and `roundTripMutation(rng)`.

## STEP 9 — per-argument encryption

Already folded into `InstrCipher.ts` — the argument keys are derived from the
**decrypted** opcode, the argument position (`A=0,B=1,C=2`) and the ip, and
use an ADD/SUB cipher while the opcode uses XOR. Nothing to change in
`buildHandlerBodies` (`s1/s2/s3` are still read before dispatch).

## STEP 10 — bootstrap junk layering + compression

* Replace `generateBootstrap(config)` with
  `generateFragmentedBootstrap({ vmSource, rng, chainSeed })`.
* Pipeline is now `base85 decode → cipher decrypt → LZSS inflate → deser VM → Real VM`
  (the producer compresses *before* ciphering, so the cipher text actually
  compresses and no compressed literal is recognisable).
* Fragment order comes from `orderFragments(frags, rng)` — a randomised
  topological sort over `provides` / `reads`.
* Junk: `emitJunkFragment(nm, rng, feeds)`.
* Anti-simplification: `emitRedundantAssign`, `emitIfTrueBlock`,
  `emitAlgebraicIdentity`.
* Blob: `longStringLevel(blob, rng)` picks a random bracket level.

---

## real_check-script additions

```js
import { roundTripInstruction, roundTripConstants } from './src/vm/InstrCipher';
import { roundTripMac, poisonValue } from './src/vm/SilentGuard';
import { roundTripLzss } from './src/vm/lzss';
import { roundTripMutation } from './src/vm/MutationTable';
import { roundTripOperandSwap } from './src/vm/Metamorphic';
import { verifyOpaquePredicates } from './src/vm/IntenseStructure';
import { verifyDeviationRoundtrip } from './src/vm/bytecode';
```

Every one of those returns a boolean; assert all of them after each step.
