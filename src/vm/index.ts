/* Barrel for the Part 1 VM upgrades.  Import from here so reg-vm-gen.ts does
 * not need ten separate import lines.  Note the .js extensions - the repo
 * builds as ESM TypeScript, so bare './bytecode' will not resolve. */

export * from './bytecode.js';
export * from './ProtoKeygen.js';
export * from './DeserCompiler.js';
export * from './InstrCipher.js';
export * from './SilentGuard.js';
export * from './Metamorphic.js';
export * from './IntenseStructure.js';
export * from './MutationTable.js';
export * from './lzss.js';
export * from './BootstrapFragments.js';
export * from './RegVMUpgrade.js';
