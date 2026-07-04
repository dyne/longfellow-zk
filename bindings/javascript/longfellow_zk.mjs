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
import { WASI } from 'node:wasi';

// -- module cache ------------------------------------------------------
let _mod = null;
let _wasmPath = null;

const DEFAULT_STDOUT = 65536;  // 64 KB
const DEFAULT_STDERR = 16384;  // 16 KB

/** Set the path to the longfellow-zk.wasm file (default: ./longfellow-zk.wasm). */
export function setWasmPath(path) {
    _wasmPath = path;
    _mod = null;  // invalidate cache
}

async function getModule() {
    if (_mod) return _mod;

    const wasmPath = _wasmPath || new URL('./longfellow-zk.wasm', import.meta.url).pathname;
    const wasmModule = await WebAssembly.compile(wasmBytes);

    const wasi = new WASI({ version: 'preview1', preopens: new Map() });
    const wasmInstance = await WebAssembly.instantiate(wasmModule, {
        wasi_snapshot_preview1: wasi.wasiImport,
    });
    wasi.initialize(wasmInstance);

    if (typeof wasmInstance.exports._initialize === 'function') {
        wasmInstance.exports._initialize();
    }

    const { memory } = wasmInstance.exports;
    if (!memory) throw new Error('WASM module does not export memory');

    _mod = { instance: wasmInstance, memory };
    return _mod;
}

// -- helpers -----------------------------------------------------------

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
    const { instance, memory } = await getModule();
    const func = instance.exports[funcName];
    if (typeof func !== 'function') {
        throw new Error(`exported function not found: ${funcName}`);
    }

    const outPtr = malloc(instance, outBytes);
    const errPtr = malloc(instance, errBytes);

    try {
        const heap = new Uint8Array(memory.buffer);
        heap.fill(0, outPtr, outPtr + outBytes);
        heap.fill(0, errPtr, errPtr + errBytes);

        // Build call args: domain args + outPtr, outLen, errPtr, errLen
        const callArgs = encodeArgs(instance, memory, argTypes, args);
        callArgs.push(outPtr, outBytes, errPtr, errBytes);

        const status = func(...callArgs);

        const result = readCString(heap, outPtr, outBytes);
        const logs = readCString(heap, errPtr, errBytes);

        if (status !== 0) {
            const err = new Error(`${funcName} failed: ${logs || 'unknown error'}`);
            err.result = result;
            err.logs = logs;
            err.status = status;
            throw err;
        }

        return { result, logs };
    } finally {
        free(instance, outPtr);
        free(instance, errPtr);
    }
}

// -- WASM heap management ---------------------------------------------

let _malloc = null;
let _free = null;
let _heapNext = 65536; // start past static data

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

function encodeArgs(instance, memory, types, values) {
    const result = [];
    for (let i = 0; i < types.length; i++) {
        const type = types[i];
        const value = values[i];
        if (type === 'number') {
            result.push(value);
        } else if (type === 'string') {
            result.push(writeStr(instance, memory, value == null ? '' : String(value)));
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
        65536 * 2,  // 128 KB output
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
