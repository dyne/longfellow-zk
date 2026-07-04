#!/usr/bin/env node
/**
 * WASM test harness for longfellow-zk
 *
 * Uses Node.js built-in WASI to load and test the WASM module.
 * Tests the full ZK workflow: generate circuit → prove → verify.
 *
 * Usage: node test/wasm_test.mjs [path/to/longfellow-zk.wasm]
 *   Defaults to ./longfellow-zk.wasm
 */

import { readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { WASI } from 'node:wasi';
import { argv, env, exit } from 'node:process';

// -- helpers -----------------------------------------------------------
const GREEN = '\x1b[0;32m';
const RED = '\x1b[0;31m';
const YELLOW = '\x1b[1;33m';
const NC = '\x1b[0m';

let pass = 0;
let fail = 0;

function ok(msg)   { console.log(`  ${GREEN}✓${NC} ${msg}`); pass++; }
function nok(msg)  { console.log(`  ${RED}✗${NC} ${msg}`); fail++; }
function info(msg) { console.log(`  ${YELLOW}→${NC} ${msg}`); }

// -- argument parsing --------------------------------------------------
const wasmPath = argv[2] || 'longfellow-zk.wasm';
const testDir = dirname(new URL(import.meta.url).pathname);
const tmpDir = join(tmpdir(), `lfzk-wasm-test-${Date.now()}`);

// -- WASI setup --------------------------------------------------------
// We map the test data directory and a temp output directory.
// WASI preopens map: guest path → host path
const preopens = new Map([
    ['/test', testDir],       // read-only test data (mdoc JSON files)
    ['/tmp', tmpDir],         // writable temp for circuit/proof output
]);

const wasi = new WASI({
    version: 'preview1',
    preopens,
    env: {},
    args: [],      // no CLI args (we call exported functions directly)
});

// -- load WASM module --------------------------------------------------
console.log(`${YELLOW}=== longfellow-zk WASM test suite ===${NC}\n`);
console.log(`WASM binary: ${wasmPath}`);
console.log(`Test data:   ${testDir}`);
console.log(`Temp dir:    ${tmpDir}`);

const wasmBytes = await readFile(wasmPath);
const wasmModule = await WebAssembly.compile(wasmBytes);
const wasmInstance = await WebAssembly.instantiate(wasmModule, {
    wasi_snapshot_preview1: wasi.wasiImport,
});

wasi.initialize(wasmInstance);

// Call _initialize if present (sets up static constructors etc.)
if (typeof wasmInstance.exports._initialize === 'function') {
    wasmInstance.exports._initialize();
}

const exports = wasmInstance.exports;
const memory = exports.memory;
if (!memory) {
    console.error('WASM module does not export "memory"');
    exit(1);
}

// -- string helpers for WASM memory -----------------------------------
const encoder = new TextEncoder();
const decoder = new TextDecoder();
let heapNext = 4096;  // start allocating past static data

function wasmStr(s) {
    // Write a UTF-8 string into WASM linear memory, return pointer.
    const bytes = encoder.encode(s + '\0');
    const ptr = heapNext;
    // Grow memory if needed
    const needed = ptr + bytes.length;
    const currentPages = memory.buffer.byteLength / 65536;
    const neededPages = Math.ceil(needed / 65536);
    if (neededPages > currentPages) {
        memory.grow(neededPages - currentPages);
    }
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    heapNext = ptr + bytes.length;
    // Align to 4 bytes
    heapNext = (heapNext + 3) & ~3;
    return ptr;
}

function wasmReadStr(ptr) {
    // Read a null-terminated UTF-8 string from WASM memory.
    const buf = new Uint8Array(memory.buffer, ptr);
    let len = 0;
    while (buf[len] !== 0 && len < 65536) len++;
    return decoder.decode(buf.subarray(0, len));
}

// -- capture stdout/stderr via WASI -----------------------------------
// WASI writes to fd 1 (stdout) and fd 2 (stderr).
// We capture stdout by checking what was written via WASI fd_read.
// For simplicity, we use the exported functions' return values and
// file-based output (prove writes to a file, generate_circuit writes
// to stdout).

let stdoutBuf = new Uint8Array(new ArrayBuffer(0));

// Override WASI fd_write to capture stdout
const origFdWrite = wasi.wasiImport['fd_write'];
wasi.wasiImport['fd_write'] = (fd, iovs, iovsLen, nwritten) => {
    // iovs is a pointer to an array of {ptr, len} pairs
    const view = new DataView(memory.buffer);
    let totalWritten = 0;
    for (let i = 0; i < iovsLen; i++) {
        const ptr = view.getUint32(iovs + i * 8, true);
        const len = view.getUint32(iovs + i * 8 + 4, true);
        const data = new Uint8Array(memory.buffer, ptr, len).slice();
        if (fd === 1) {
            // append to stdout buffer
            const combined = new Uint8Array(stdoutBuf.length + data.length);
            combined.set(stdoutBuf);
            combined.set(data, stdoutBuf.length);
            stdoutBuf = combined;
        }
        totalWritten += len;
    }
    view.setUint32(nwritten, totalWritten, true);
    return 0;
};

function flushStdout() {
    const text = decoder.decode(stdoutBuf);
    stdoutBuf = new Uint8Array(new ArrayBuffer(0));
    return text;
}

// -- test functions ----------------------------------------------------
async function runTest(name, fn) {
    try {
        await fn();
        ok(name);
    } catch (e) {
        nok(`${name} — ${e.message}`);
    }
}

function assert(cond, msg) {
    if (!cond) throw new Error(msg);
}

// Map test data paths to WASI guest paths
function wasiPath(localFile) {
    // test data files are in test/ directory
    return `/test/${localFile}`;
}

function wasiTmp(file) {
    return `/tmp/${file}`;
}

// -- tests -------------------------------------------------------------

// Test 1: Generate circuit for zkspec 0
console.log(`\n--- Circuit generation ---`);

let circuit0Str = '';
await runTest('Generate circuit for zkspec 0', async () => {
    const rc = exports.wasm_generate_circuit(0);
    circuit0Str = flushStdout().trim();
    assert(rc === 0, `exit code ${rc}`);
    assert(circuit0Str.length > 0, 'no output');
    const c = JSON.parse(circuit0Str);
    assert(c.circuit_data_base64, 'missing circuit_data_base64');
    assert(c._zkspec?.index === 0, `wrong zkspec: ${c._zkspec?.index}`);
    info(`circuit size: ${c._circuit_size} bytes`);
});

// Test 2: Generate circuit for zkspec 1
let circuit1Str = '';
await runTest('Generate circuit for zkspec 1', async () => {
    const rc = exports.wasm_generate_circuit(1);
    circuit1Str = flushStdout().trim();
    assert(rc === 0, `exit code ${rc}`);
    const c = JSON.parse(circuit1Str);
    assert(c._zkspec?.index === 1, `wrong zkspec: ${c._zkspec?.index}`);
});

// Write circuits to temp files so prove/verify can read them
const circuit0Path = wasiTmp('circuit_0.json');
const circuit1Path = wasiTmp('circuit_1.json');
await writeFile(join(tmpDir, 'circuit_0.json'), circuit0Str);
await writeFile(join(tmpDir, 'circuit_1.json'), circuit1Str);

// Test 3: Prove with mdoc_00 (1 attribute)
console.log(`\n--- Proof generation ---`);

const mdoc00Path = wasiPath('mdoc_00.json');
const proof00Path = wasiTmp('proof_00.json');

await runTest('Generate proof with mdoc_00', async () => {
    const rc = exports.wasm_generate_proof(
        wasmStr(circuit0Path),
        wasmStr(mdoc00Path),
        wasmStr(proof00Path)
    );
    assert(rc === 0, `exit code ${rc}`);
    // Check that proof file was written
    const proofData = await readFile(join(tmpDir, 'proof_00.json'), 'utf8');
    const p = JSON.parse(proofData);
    assert(p.proof_data_base64, 'missing proof_data_base64');
    assert(p.proof_data_base64.length > 100, `proof too short: ${p.proof_data_base64.length} chars`);
    info(`proof base64 length: ${p.proof_data_base64.length} chars`);
});

// Test 4: Verify proof from mdoc_00
console.log(`\n--- Proof verification ---`);

await runTest('Verify proof from mdoc_00', async () => {
    const rc = exports.wasm_verify_proof(
        wasmStr(circuit0Path),
        wasmStr(proof00Path)
    );
    const output = flushStdout().trim();
    assert(rc === 0, `exit code ${rc}, output: ${output}`);
    assert(output.includes('successful'), `unexpected output: ${output}`);
});

// Test 5: Prove with mdoc_04 (different doc type — wallet idcard)
const mdoc04Path = wasiPath('mdoc_04.json');
const proof04Path = wasiTmp('proof_04.json');

await runTest('Generate proof with mdoc_04 (idcard)', async () => {
    const rc = exports.wasm_generate_proof(
        wasmStr(circuit0Path),
        wasmStr(mdoc04Path),
        wasmStr(proof04Path)
    );
    assert(rc === 0, `exit code ${rc}`);
    const proofData = await readFile(join(tmpDir, 'proof_04.json'), 'utf8');
    assert(JSON.parse(proofData).proof_data_base64, 'missing proof_data_base64');
});

// Test 6: Verify proof from mdoc_04
await runTest('Verify proof from mdoc_04', async () => {
    const rc = exports.wasm_verify_proof(
        wasmStr(circuit0Path),
        wasmStr(proof04Path)
    );
    const output = flushStdout().trim();
    assert(rc === 0, `exit code ${rc}`);
    assert(output.includes('successful'), `unexpected output: ${output}`);
});

// Test 7: Failure — mismatched zkspec
console.log(`\n--- Failure cases ---`);

await runTest('Verify fails with wrong zkspec circuit', async () => {
    // Verify proof_00 (zkspec 0) against circuit_1 (zkspec 1)
    const rc = exports.wasm_verify_proof(
        wasmStr(circuit1Path),
        wasmStr(proof00Path)
    );
    assert(rc !== 0, `expected non-zero exit code, got ${rc}`);
});

// Test 8: Failure — missing file
await runTest('Prove fails with missing files', async () => {
    const rc = exports.wasm_generate_proof(
        wasmStr(wasiTmp('nonexistent.json')),
        wasmStr(wasiTmp('nonexistent.json')),
        wasmStr(wasiTmp('out.json'))
    );
    assert(rc !== 0, `expected non-zero exit code, got ${rc}`);
});

// -- summary -----------------------------------------------------------
console.log(`\n${YELLOW}=== Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC} ${YELLOW}===${NC}`);
exit(fail > 0 ? 1 : 0);
