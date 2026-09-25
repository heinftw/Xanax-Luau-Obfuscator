import type { RegBytecodeChunk } from './bytecode.js';
import { REG_OPCODE_COUNT } from './bytecode.js';
import { deriveProtoSeed, xorshift32 } from './ProtoKeygen.js';

export interface DerivedTableNames {
  fn: string;
  nBxor: string;
  nBand: string;
  nLshift: string;
  nRshift: string;
  nFloor: string;
}

export function emitDerivedTableRuntimeLua(
  n: DerivedTableNames,
  masterSeed: number
): string {
  const { fn, nBxor, nBand, nLshift, nRshift, nFloor } = n;

  return [
    `local function _mul32(a,b)`,
    ` local al=a%65536 local ah=(a-al)/65536`,
    ` local bl=b%65536 local bh=(b-bl)/65536`,
    ` local ll=al*bl`,
    ` local m=al*bh+ah*bl`,
    ` return (ll+(m%65536)*65536)%4294967296`,
    `end`,
    `local function _seed(ti,dp)`,
    ` local h=${nBxor}(${masterSeed >>> 0},0x7a55c1)`,
    ` h=_mul32(${nBxor}(h,ti+0x4f2b1c),0x85ebca6b)`,
    ` h=${nBxor}(h,${nRshift}(h,13))`,
    ` h=_mul32(${nBxor}(h,dp+0x019d3a),0xc2b2ae35)`,
    ` h=${nBxor}(h,${nRshift}(h,16))`,
    ` h=${nBxor}(_mul32(h,0x27d4eb2f),0x2545f491)`,
    ` return h`,
    `end`,
    `local function ${fn}(ti,dp)`,
    ` local s=_seed(ti,dp)`,
    ` if s==0 then s=2654435769 end`,
    ` local t={}`,
    ` for _i=0,${REG_OPCODE_COUNT - 1} do t[_i+1]=_i end`,
    ` for _i=${REG_OPCODE_COUNT - 1},1,-1 do`,
    `  s=${nBand}(${nBxor}(s,${nLshift}(s,13)),0xFFFFFFFF)`,
    `  s=${nBxor}(s,${nRshift}(s,17))`,
    `  s=${nBand}(${nBxor}(s,${nLshift}(s,5)),0xFFFFFFFF)`,
    `  local _j=${nFloor}((s/4294967296)*(_i+1))`,
    `  local _v=t[_i+1] t[_i+1]=t[_j+1] t[_j+1]=_v`,
    ` end`,
    ` local d={}`,
    ` for _i=1,${REG_OPCODE_COUNT} do d[t[_i]+1]=_i-1 end`,
    ` return d`,
    `end`,
  ].join('\n');
}

export function emitDerivedTableRefLua(
  p: RegBytecodeChunk,
  fn: string
): string {
  const ti = p.treeIndex ?? 0;
  const dp = p.depth ?? 0;
  return `${fn}(${ti},${dp})`;
}

export function expectedDecodeTable(
  masterSeed: number,
  treeIndex: number,
  depth: number
): number[] {
  const seed = deriveProtoSeed(masterSeed, treeIndex, depth);
  const rng = xorshift32(seed);
  const t = Array.from({ length: REG_OPCODE_COUNT }, (_, i) => i);
  for (let i = REG_OPCODE_COUNT - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = t[i];
    t[i] = t[j];
    t[j] = tmp;
  }
  const d = new Array<number>(REG_OPCODE_COUNT).fill(0);
  for (let i = 0; i < REG_OPCODE_COUNT; i++) d[t[i]] = i;
  return d;
}

export function emitDispatchDecodeLua(
  nDecodeTable: string,
  nOp: string,
  nBxor: string
): string {
  return [
    `${nOp}=${nDecodeTable}[${nOp}+1]-1`,
    `if ${nOp}==nil then ${nOp}=${nBxor}(${nOp},0xFF) end`,
  ].join('\n');
}

export interface DerivedTableCheck {
  ok: boolean;
  detail: string;
}

export function verifyDerivedTables(
  masterSeed: number,
  samples = 24
): DerivedTableCheck {
  const mul32 = (a: number, b: number): number => {
    const al = a % 65536;
    const ah = (a - al) / 65536;
    const bl = b % 65536;
    const bh = (b - bl) / 65536;
    const ll = al * bl;
    const m = al * bh + ah * bl;
    return (ll + (m % 65536) * 65536) % 4294967296;
  };

  const bx = (a: number, b: number) => (a ^ b) >>> 0;
  const rs = (a: number, n: number) => a >>> n;
  const ls = (a: number, n: number) => (a << n) >>> 0;

  const luaSeed = (ti: number, dp: number): number => {
    let h = bx(masterSeed >>> 0, 0x7a55c1);
    h = mul32(bx(h, ti + 0x4f2b1c), 0x85ebca6b);
    h = bx(h, rs(h, 13));
    h = mul32(bx(h, dp + 0x019d3a), 0xc2b2ae35);
    h = bx(h, rs(h, 16));
    h = bx(mul32(h, 0x27d4eb2f), 0x2545f491);
    return h >>> 0;
  };

  for (let s = 0; s < samples; s++) {
    const ti = (s * 7919) % 1000;
    const dp = s % 6;

    let st = luaSeed(ti, dp);
    if (st === 0) st = 2654435769;
    const t = Array.from({ length: REG_OPCODE_COUNT }, (_, i) => i);
    for (let i = REG_OPCODE_COUNT - 1; i > 0; i--) {
      st = bx(st, ls(st, 13)) >>> 0;
      st = bx(st, rs(st, 17)) >>> 0;
      st = bx(st, ls(st, 5)) >>> 0;
      const j = Math.floor((st / 4294967296) * (i + 1));
      const tmp = t[i];
      t[i] = t[j];
      t[j] = tmp;
    }
    const d = new Array<number>(REG_OPCODE_COUNT).fill(0);
    for (let i = 0; i < REG_OPCODE_COUNT; i++) d[t[i]] = i;

    const want = expectedDecodeTable(masterSeed, ti, dp);
    for (let i = 0; i < REG_OPCODE_COUNT; i++) {
      if (d[i] !== want[i]) {
        return {
          ok: false,
          detail: `mismatch at ti=${ti} dp=${dp} slot=${i}: lua=${d[i]} ts=${want[i]}`,
        };
      }
    }
  }

  return { ok: true, detail: `${samples} samples x ${REG_OPCODE_COUNT} slots agree` };
}
