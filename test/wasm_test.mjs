#!/usr/bin/env node
/**
 * WASM test suite for longfellow-zk (zenroom-style tobuf API).
 *
 * Uses the JS bindings (bindings/javascript/longfellow_zk.mjs) which
 * wrap the _tobuf WASM functions with pre-allocated heap buffers.
 *
 * Usage: node test/wasm_test.mjs [path/to/longfellow-zk.wasm]
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { exit, argv } from 'node:process';
import { generateCircuit, generateProof, verifyProof, setWasmPath } from '../bindings/javascript/longfellow_zk.mjs';

// -- configure WASM binary path ---------------------------------------
const wasmPath = argv[2] || 'longfellow-zk.wasm';
setWasmPath(wasmPath);

// -- helpers -----------------------------------------------------------
const GREEN = '\x1b[0;32m';
const RED   = '\x1b[0;31m';
const YELLOW = '\x1b[1;33m';
const NC = '\x1b[0m';

let pass = 0;
let fail = 0;

function ok(msg)   { console.log(`  ${GREEN}✓${NC} ${msg}`); pass++; }
function nok(msg)  { console.log(`  ${RED}✗${NC} ${msg}`); fail++; }
function info(msg) { console.log(`  ${YELLOW}→${NC} ${msg}`); }

// -- load test fixture -------------------------------------------------
const testDir = dirname(new URL(import.meta.url).pathname);

async function loadMdoc(filename) {
    const raw = await readFile(join(testDir, filename), 'utf8');
    return JSON.parse(raw);
}

function base64ToBytes(b64) {
    return Uint8Array.from(Buffer.from(b64, 'base64'));
}

function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// -- tests -------------------------------------------------------------
console.log(`${YELLOW}=== longfellow-zk WASM test suite (tobuf API) ===${NC}\n`);

// Test 1: Generate circuit
console.log('--- Circuit generation ---');

let circuitHex = '';
let circuitJson = null;

try {
    const { result } = await generateCircuit(0);
    circuitJson = JSON.parse(result);
    circuitHex = circuitJson.circuit_data_hex;
    if (!circuitHex) throw new Error('missing circuit_data_hex');
    ok('Generate circuit for zkspec 0');
    info(`circuit hex length: ${circuitHex.length} chars (${circuitJson._circuit_size} bytes)`);
} catch (e) {
    nok(`Generate circuit for zkspec 0 — ${e.message}`);
}

// Test 2: Generate circuit for zkspec 1
let circuit1Hex = '';
try {
    const { result } = await generateCircuit(1);
    const c = JSON.parse(result);
    circuit1Hex = c.circuit_data_hex;
    if (c._zkspec?.index !== 1) throw new Error(`wrong zkspec: ${c._zkspec?.index}`);
    ok('Generate circuit for zkspec 1');
} catch (e) {
    nok(`Generate circuit for zkspec 1 — ${e.message}`);
}

// Test 3: Prove with mdoc_00
console.log('\n--- Proof generation ---');

let proof00 = null;
try {
    const mdoc = await loadMdoc('mdoc_00.json');
    const mdocHex = bytesToHex(base64ToBytes(mdoc.mdoc_data_base64));
    const transcriptHex = mdoc.transcript.replace(/^0x/, '');

    const attrs = (mdoc.attributes || []).map(a => ({
        namespace: a.namespace,
        id: a.id,
        cbor_value: a.cbor_value.replace(/^0x/, ''),
    }));

    const { result } = await generateProof({
        circuitHex,
        mdocHex,
        pkxHex: mdoc.public_key.x,
        pkyHex: mdoc.public_key.y,
        transcriptHex,
        time: mdoc.time,
        docType: mdoc.doc_type,
        zkspecIndex: mdoc.zkspec,
        attributes: attrs,
    });

    proof00 = JSON.parse(result);
    if (!proof00.proof_data_hex) throw new Error('missing proof_data_hex');
    ok('Generate proof with mdoc_00');
    info(`proof hex length: ${proof00.proof_data_hex.length} chars`);
} catch (e) {
    nok(`Generate proof with mdoc_00 — ${e.message}`);
}

// Test 4: Verify proof from mdoc_00
console.log('\n--- Proof verification ---');

if (proof00) {
    try {
        const mdoc = await loadMdoc('mdoc_00.json');
        const transcriptHex = mdoc.transcript.replace(/^0x/, '');

        const attrs = (mdoc.attributes || []).map(a => ({
            namespace: a.namespace,
            id: a.id,
            cbor_value: a.cbor_value.replace(/^0x/, ''),
        }));

        const { result } = await verifyProof({
            circuitHex,
            proofHex: proof00.proof_data_hex,
            pkxHex: mdoc.public_key.x,
            pkyHex: mdoc.public_key.y,
            transcriptHex,
            time: mdoc.time,
            docType: mdoc.doc_type,
            zkspecIndex: mdoc.zkspec,
            attributes: attrs,
        });

        const vr = JSON.parse(result);
        if (!vr.result?.includes('successful')) throw new Error(`unexpected: ${result}`);
        ok('Verify proof from mdoc_00');
    } catch (e) {
        nok(`Verify proof from mdoc_00 — ${e.message}`);
    }
}

// Test 5: Prove and verify with mdoc_01 (same zkspec, different data)
console.log('\n--- Cross-document test ---');

let proof01 = null;
try {
    const mdoc = await loadMdoc('mdoc_01.json');
    const mdocHex = bytesToHex(base64ToBytes(mdoc.mdoc_data_base64));
    const transcriptHex = mdoc.transcript.replace(/^0x/, '');

    const { result } = await generateProof({
        circuitHex,
        mdocHex,
        pkxHex: mdoc.public_key.x,
        pkyHex: mdoc.public_key.y,
        transcriptHex,
        time: mdoc.time,
        docType: mdoc.doc_type,
        zkspecIndex: mdoc.zkspec,
        attributes: (mdoc.attributes || []).map(a => ({
            namespace: a.namespace,
            id: a.id,
            cbor_value: a.cbor_value.replace(/^0x/, ''),
        })),
    });

    proof01 = JSON.parse(result);
    ok('Generate proof with mdoc_01');

    const { result: vr } = await verifyProof({
        circuitHex,
        proofHex: proof01.proof_data_hex,
        pkxHex: mdoc.public_key.x,
        pkyHex: mdoc.public_key.y,
        transcriptHex,
        time: mdoc.time,
        docType: mdoc.doc_type,
        zkspecIndex: mdoc.zkspec,
        attributes: (mdoc.attributes || []).map(a => ({
            namespace: a.namespace,
            id: a.id,
            cbor_value: a.cbor_value.replace(/^0x/, ''),
        })),
    });

    const parsed = JSON.parse(vr);
    if (!parsed.result?.includes('successful')) throw new Error(`unexpected: ${vr}`);
    ok('Verify proof from mdoc_01');
} catch (e) {
    nok(`Cross-document test — ${e.message}`);
}

// Test 6: Failure — mismatched zkspec
console.log('\n--- Failure cases ---');

if (proof00 && circuit1Hex) {
    try {
        const mdoc = await loadMdoc('mdoc_00.json');
        const transcriptHex = mdoc.transcript.replace(/^0x/, '');
        await verifyProof({
            circuitHex: circuit1Hex,
            proofHex: proof00.proof_data_hex,
            pkxHex: mdoc.public_key.x,
            pkyHex: mdoc.public_key.y,
            transcriptHex,
            time: mdoc.time,
            docType: mdoc.doc_type,
            zkspecIndex: mdoc.zkspec,
            attributes: [],
        });
        nok('Verify fails with wrong zkspec — expected error, got success');
    } catch (e) {
        ok('Verify fails with wrong zkspec circuit');
    }
}

// Test 7: Invalid hex input
try {
    await generateProof({
        circuitHex: 'not-hex!',
        mdocHex: 'aa',
        pkxHex: 'aa',
        pkyHex: 'aa',
        transcriptHex: 'aa',
        time: 'now',
        docType: 'x',
        zkspecIndex: 0,
        attributes: [],
    });
    nok('Invalid hex input — expected error, got success');
} catch (e) {
    ok('Rejects invalid hex input');
}

// -- summary -----------------------------------------------------------
console.log(`\n${YELLOW}=== Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC} ${YELLOW}===${NC}`);
exit(fail > 0 ? 1 : 0);
