import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const wasmPath = process.argv[2];
if (!wasmPath) throw new Error('usage: node test/wasi_smoke.mjs PATH_TO_WASM');

const bytes = await readFile(wasmPath);
const wasi = new WASI({ version: 'preview1' });
const { instance } = await WebAssembly.instantiate(bytes, wasi.getImportObject());
if (instance.exports.longfellow_zk_wasi_smoke() !== 42) {
  throw new Error('WASI smoke export returned an unexpected value');
}
console.log('WASI Node smoke passed');
