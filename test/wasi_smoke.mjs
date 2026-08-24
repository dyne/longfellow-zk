import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const baseWasmPath = process.argv[2];
const ecdsaWasmPath = process.argv[3];
if (!baseWasmPath || !ecdsaWasmPath) {
  throw new Error(
    'usage: node test/wasi_smoke.mjs PATH_TO_BASE_WASM PATH_TO_ECDSA_WASM',
  );
}

async function instantiateWasi(wasmPath) {
  const bytes = await readFile(wasmPath);
  const wasi = new WASI({ version: 'preview1' });
  const { instance } = await WebAssembly.instantiate(bytes, wasi.getImportObject());
  wasi.initialize(instance);
  return instance;
}

const base = await instantiateWasi(baseWasmPath);
if (base.exports.longfellow_zk_wasi_smoke() !== 42) {
  throw new Error('WASI smoke export returned an unexpected value');
}

const ecdsa = await instantiateWasi(ecdsaWasmPath);
const verifyResult = ecdsa.exports.longfellow_zk_ecdsa_wasi_verify();
if (verifyResult !== 0) {
  throw new Error(`WASI ECDSA verifier failed with code ${verifyResult}`);
}

console.log('WASI base link and ECDSA verification smoke passed');
