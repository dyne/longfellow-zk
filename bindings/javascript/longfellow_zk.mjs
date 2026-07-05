/**
 * longfellow-zk WASM bindings for Node.js
 *
 * Uses the zenroom-style _tobuf pattern: all binary data is lowercase hex,
 * results are written to pre-allocated WASM heap buffers.
 *
 * Usage:
 *   import { generateCircuit, generateProof, verifyProof } from './longfellow_zk.mjs';
 *   const { result } = await generateCircuit(0);
 */

import { readFile } from 'node:fs/promises';
import { randomFillSync } from 'node:crypto';

// -- module cache ------------------------------------------------------
let _mod = null;
let _wasmPath = null;

const DEFAULT_STDOUT = 65536;   // 64 KB (for verify/small outputs)
const CIRCUIT_STDOUT = 8388608;  // 8 MB (circuit JSON can be large)
const PROOF_STDOUT = 2097152;    // 2 MB (proof output)
const DEFAULT_STDERR = 16384;   // 16 KB

// -- minimal WASI shim (avoids Node.js WASI segfault) -----------------
function makeWasiImports(memRef) {
    // Minimal WASI preview1 shim.
    // memRef is { memory: WebAssembly.Memory } — we read .buffer fresh each
    // call because it changes when the WASM module grows memory.
    const buf = () => memRef.memory.buffer;
    return {
        fd_write(fd, iovsPtr, iovsLen, nwrittenPtr) {
            const view = new DataView(buf());
            const chunks = [];
            let total = 0;
            for (let i = 0; i < iovsLen; i++) {
                const ptr = view.getUint32(iovsPtr + i * 8, true);
                const len = view.getUint32(iovsPtr + i * 8 + 4, true);
                chunks.push(new Uint8Array(buf(), ptr, len));
                total += len;
            }
            if (fd === 1 || fd === 2) {
                const output = decoder.decode(concatBytes(chunks, total));
                if (fd === 1) memRef.stdout += output;
                if (fd === 2) memRef.stderr += output;
            }
            view.setUint32(nwrittenPtr, total, true);
            return 0;
        },
        fd_close() { return 0; },
        fd_seek() { return 70; },
        fd_read() { return 0; },
        fd_fdstat_get(fd, bufPtr) {
            const b = new Uint8Array(buf(), bufPtr, 24);
            b.fill(0);
            b[0] = 2; // filetype: character_device
            return 0;
        },
        proc_exit() {},
        environ_sizes_get() { return 0; },
        environ_get() { return 0; },
        args_sizes_get() { return 0; },
        args_get() { return 0; },
        clock_time_get() { return 0; },
        random_get(bufPtr, bufLen) {
            randomFillSync(new Uint8Array(buf(), bufPtr, bufLen));
            return 0;
        },
    };
}

/** Set the path to the longfellow-zk.wasm file (default: ./longfellow-zk.wasm). */
export function setWasmPath(path) {
    _wasmPath = path;
    _mod = null;  // invalidate cache
}

async function getModule() {
    if (_mod) return _mod;

    const wasmPath = _wasmPath || new URL('./longfellow-zk.wasm', import.meta.url).pathname;
    const wasmBytes = await readFile(wasmPath);
    const wasmModule = await WebAssembly.compile(wasmBytes);

    // Use a mutable reference so WASI imports can access memory after instantiation
    // Store the memory object (not the buffer) so we always get the current buffer
    const memRef = { memory: null, stdout: '', stderr: '' };
    const wasmInstance = await WebAssembly.instantiate(wasmModule, {
        wasi_snapshot_preview1: makeWasiImports(memRef),
    });
    memRef.memory = wasmInstance.exports.memory;

    if (typeof wasmInstance.exports._initialize === 'function') {
        wasmInstance.exports._initialize();
    }

    const { memory } = wasmInstance.exports;
    if (!memory) throw new Error('WASM module does not export memory');

    if (_heapNext === null) {
        _heapNext = getHeapBase(wasmInstance);
    }

    _mod = { instance: wasmInstance, memory, memRef };
    return _mod;
}

// -- helpers -----------------------------------------------------------

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function concatBytes(chunks, total) {
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
    }
    return bytes;
}

function readCString(heap, ptr, maxLen) {
    for (let i = 0; i < maxLen; i++) {
        if (heap[ptr + i] === 0) {
            return decoder.decode(heap.subarray(ptr, ptr + i));
        }
    }
    return decoder.decode(heap.subarray(ptr, ptr + maxLen));
}

function assertHex(label, value) {
    if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) {
        throw new Error(`${label}: invalid hex string`);
    }
}

// -- callBufferApi -----------------------------------------------------

/**
 * Call a _tobuf function with pre-allocated WASM heap buffers.
 *
 * @param {string} funcName - exported function name (e.g., "longfellow_zk_generate_circuit_tobuf")
 * @param {string[]} argTypes  - argument types for ccall-like signature
 * @param {Array}    args      - argument values
 * @param {number}   outBytes  - bytes to allocate for stdout buffer
 * @param {number}   errBytes  - bytes to allocate for stderr buffer
 * @returns {{ result: string, logs: string }}
 */
async function callBufferApi(funcName, argTypes, args, outBytes, errBytes) {
    const { instance, memory, memRef } = await getModule();
    const func = instance.exports[funcName];
    if (typeof func !== 'function') {
        throw new Error(`exported function not found: ${funcName}`);
    }

    const outPtr = malloc(instance, outBytes);
    const errPtr = malloc(instance, errBytes);
    const argPtrs = [];

    try {
        // Zero out the buffers (must use fresh view each time)
        new Uint8Array(memory.buffer, outPtr, outBytes).fill(0);
        new Uint8Array(memory.buffer, errPtr, errBytes).fill(0);

        // Build call args: domain args + outPtr, outLen, errPtr, errLen
        const callArgs = encodeArgs(instance, memory, argTypes, args, argPtrs);
        callArgs.push(outPtr, outBytes, errPtr, errBytes);

        const status = func(...callArgs);

        // Read results from CURRENT memory buffer (may have grown during call)
        const heap = new Uint8Array(memory.buffer);
        const result = readCString(heap, outPtr, outBytes);
        const errText = readCString(heap, errPtr, errBytes);
        const logs = [errText, memRef.stderr].filter(Boolean).join('\n');
        memRef.stdout = '';
        memRef.stderr = '';

        if (status !== 0) {
            const err = new Error(`${funcName} failed: ${logs || 'unknown error'}`);
            err.result = result;
            err.logs = logs;
            err.status = status;
            throw err;
        }

        return { result, logs };
    } finally {
        for (const ptr of argPtrs) {
            free(instance, ptr);
        }
        free(instance, outPtr);
        free(instance, errPtr);
    }
}

// -- WASM heap management ---------------------------------------------

let _malloc = null;
let _free = null;
let _heapNext = null;  // will be set from __heap_base after init

function getHeapBase(instance) {
    // Read __heap_base export if available, otherwise fall back to a safe offset
    if (typeof instance.exports.__heap_base !== 'undefined') {
        return instance.exports.__heap_base.value;
    }
    // With --stack-first and 16MB stack: safe to start at 32MB
    return 32 * 1024 * 1024;
}

function malloc(instance, bytes) {
    // Try to use exported malloc if available (Emscripten pattern)
    if (_malloc === null) {
        _malloc = instance.exports.malloc || null;
    }
    if (_malloc) {
        return _malloc(bytes);
    }
    // Fallback: bump allocator
    const ptr = _heapNext;
    _heapNext += bytes;
    _heapNext = (_heapNext + 7) & ~7; // 8-byte align
    return ptr;
}

function free(instance, ptr) {
    if (_free === null) {
        _free = instance.exports.free || null;
    }
    if (_free) {
        _free(ptr);
    }
    // bump allocator: no-op
}

function writeStr(instance, memory, s) {
    const bytes = encoder.encode(s + '\0');
    const ptr = malloc(instance, bytes.length);
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
}

// -- argument encoding ------------------------------------------------

function encodeArgs(instance, memory, types, values, argPtrs) {
    const result = [];
    for (let i = 0; i < types.length; i++) {
        const type = types[i];
        const value = values[i];
        if (type === 'number') {
            result.push(value);
        } else if (type === 'string') {
            const ptr = writeStr(instance, memory, value == null ? '' : String(value));
            argPtrs.push(ptr);
            result.push(ptr);
        } else {
            result.push(value);
        }
    }
    return result;
}

// -- public API --------------------------------------------------------

/**
 * Generate a ZK circuit for the given zkspec index.
 *
 * @param {number} zkspecIndex - ZK spec index (0-7)
 * @returns {Promise<{result: string, logs: string}>} result is JSON string
 */
export async function generateCircuit(zkspecIndex) {
    return callBufferApi(
        'longfellow_zk_generate_circuit_tobuf',
        ['number'],
        [zkspecIndex],
        CIRCUIT_STDOUT,
        DEFAULT_STDERR
    );
}

/**
 * Compile the imported BIP340 circuit inside WASM as a smoke test.
 *
 * @returns {Promise<{result: string, logs: string}>} result is JSON string
 */
export async function bip340Smoke() {
    return callBufferApi(
        'longfellow_zk_bip340_smoke_tobuf',
        [],
        [],
        DEFAULT_STDOUT,
        DEFAULT_STDERR
    );
}

/**
 * Generate a ZK proof.
 *
 * @param {object} params
 * @param {string} params.circuitHex   - hex-encoded circuit binary
 * @param {string} params.mdocHex      - hex-encoded mDoc binary
 * @param {string} params.pkxHex       - hex-encoded public key X
 * @param {string} params.pkyHex       - hex-encoded public key Y
 * @param {string} params.transcriptHex - hex-encoded transcript
 * @param {string} params.time         - ISO 8601 timestamp
 * @param {string} params.docType      - document type
 * @param {number} params.zkspecIndex  - ZK spec index
 * @param {object[]} [params.attributes] - array of requested attributes
 * @returns {Promise<{result: string, logs: string}>} result is JSON string
 */
export async function generateProof({
    circuitHex, mdocHex,
    pkxHex, pkyHex,
    transcriptHex,
    time, docType, zkspecIndex,
    attributes,
}) {
    assertHex('circuitHex', circuitHex);
    assertHex('mdocHex', mdocHex);
    assertHex('transcriptHex', transcriptHex);

    const attrsJson = attributes ? JSON.stringify(attributes) : '';

    return callBufferApi(
        'longfellow_zk_generate_proof_tobuf',
        ['string', 'string', 'string', 'string', 'string', 'string', 'string', 'number', 'string'],
        [circuitHex, mdocHex, pkxHex, pkyHex, transcriptHex, time, docType, zkspecIndex, attrsJson],
        PROOF_STDOUT,
        DEFAULT_STDERR
    );
}

/**
 * Verify a ZK proof.
 *
 * @param {object} params
 * @param {string} params.circuitHex   - hex-encoded circuit binary
 * @param {string} params.proofHex     - hex-encoded proof binary
 * @param {string} params.pkxHex       - hex-encoded public key X
 * @param {string} params.pkyHex       - hex-encoded public key Y
 * @param {string} params.transcriptHex - hex-encoded transcript
 * @param {string} params.time         - ISO 8601 timestamp
 * @param {string} params.docType      - document type
 * @param {number} params.zkspecIndex  - ZK spec index
 * @param {object[]} [params.attributes] - array of requested attributes
 * @returns {Promise<{result: string, logs: string}>} result is JSON string
 */
export async function verifyProof({
    circuitHex, proofHex,
    pkxHex, pkyHex,
    transcriptHex,
    time, docType, zkspecIndex,
    attributes,
}) {
    assertHex('circuitHex', circuitHex);
    assertHex('proofHex', proofHex);
    assertHex('transcriptHex', transcriptHex);

    const attrsJson = attributes ? JSON.stringify(attributes) : '';

    return callBufferApi(
        'longfellow_zk_verify_proof_tobuf',
        ['string', 'string', 'string', 'string', 'string', 'string', 'string', 'number', 'string'],
        [circuitHex, proofHex, pkxHex, pkyHex, transcriptHex, time, docType, zkspecIndex, attrsJson],
        DEFAULT_STDOUT,
        DEFAULT_STDERR
    );
}

export { bytesToHex, hexToBytes, utf8ToHex, hexToUtf8 } from './encoding.mjs';
