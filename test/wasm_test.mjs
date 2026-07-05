#!/usr/bin/env node
/**
 * WASM test suite for longfellow-zk (zenroom-style tobuf API).
 *
 * Uses the JS bindings (bindings/javascript/longfellow_zk.mjs) which
 * wrap the _tobuf WASM functions with pre-allocated heap buffers.
 *
 * Usage: node test/wasm_test.mjs [--suite bip340|mdoc|all] [path/to/longfellow-zk.wasm]
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { exit, argv } from 'node:process';
import { performance } from 'node:perf_hooks';
import { bip340Smoke, generateCircuit, generateProof, verifyProof, setWasmPath } from '../bindings/javascript/longfellow_zk.mjs';

// -- configure WASM binary path ---------------------------------------
const suites = new Set(['bip340', 'mdoc', 'all']);
let suite = 'all';
const positional = [];
for (let i = 2; i < argv.length; ++i) {
    const arg = argv[i];
    if (arg === '--suite') {
        suite = argv[++i] || '';
    } else if (arg.startsWith('--suite=')) {
        suite = arg.slice('--suite='.length);
    } else {
        positional.push(arg);
    }
}

if (!suites.has(suite)) {
    console.error(`invalid suite: ${suite || '(empty)'}; expected bip340, mdoc, or all`);
    exit(2);
}

const runBip340 = suite === 'bip340' || suite === 'all';
const runMdoc = suite === 'mdoc' || suite === 'all';
const wasmPath = positional[0] || 'longfellow-zk.wasm';
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

function compressedBytes(hex) {
    return hex ? hex.length / 2 : 0;
}

function metricList(metrics) {
    return metrics.filter(Boolean).join(', ');
}

async function wasmStep(label, fn, metricsFn = () => '') {
    const started = performance.now();
    try {
        const value = await fn();
        const elapsed = Math.round(performance.now() - started);
        const metrics = metricList([`${elapsed} ms`, metricsFn(value)]);
        info(`${label}: ${metrics}`);
        return value;
    } catch (e) {
        const elapsed = Math.round(performance.now() - started);
        let sizeMetrics = '';
        try {
            sizeMetrics = metricsFn();
        } catch {
            sizeMetrics = '';
        }
        const metrics = metricList([`${elapsed} ms`, sizeMetrics, 'failed']);
        info(`${label}: ${metrics}`);
        throw e;
    }
}

function circuitMetrics(hex) {
    return `compressed bytes: circuit=${compressedBytes(hex)}`;
}

function proofMetrics(hex) {
    return `compressed bytes: proof=${compressedBytes(hex)}`;
}

function verifyMetrics(circuitHexValue, proofHexValue) {
    return `compressed bytes: circuit=${compressedBytes(circuitHexValue)}, proof=${compressedBytes(proofHexValue)}`;
}

function stepMetrics(step) {
    const metrics = [`${step.ms} ms`];
    if (Number.isFinite(step.compressed_bytes)) {
        metrics.push(`compressed bytes=${step.compressed_bytes}`);
    }
    return metricList(metrics);
}

function logBip340Steps(r) {
    for (const step of r.steps || []) {
        info(`BIP340 ${step.name}: ${stepMetrics(step)}`);
    }
}

// -- tests -------------------------------------------------------------
console.log(`${YELLOW}=== longfellow-zk WASM test suite (${suite}, tobuf API) ===${NC}\n`);

// Test 0: BIP340 smoke path
if (runBip340) {
    console.log('--- BIP340 circuit smoke ---');

    try {
        const { result } = await wasmStep(
            'BIP340 smoke',
            () => bip340Smoke(),
            ({ result }) => {
                const r = JSON.parse(result);
                return `${verifyMetrics(r.circuit_data_hex, r.proof_data_hex)}, public inputs=${r.public_inputs}, total inputs=${r.total_inputs}, quad terms=${r.quad_terms}`;
            }
        );
        const r = JSON.parse(result);
        if (!r.result?.includes('successful')) throw new Error(`unexpected: ${result}`);
        if (!r.circuit_data_hex) throw new Error('missing BIP340 circuit_data_hex');
        if (!r.proof_data_hex) throw new Error('missing BIP340 proof_data_hex');
        logBip340Steps(r);
        ok('Run BIP340 smoke in WASM');
    } catch (e) {
        nok(`Run BIP340 smoke in WASM — ${e.message}`);
    }
}

// Test 1: Generate circuit
if (runMdoc) {
    console.log('--- mdoc circuit generation ---');

    let circuitHex = '';
    let circuitJson = null;

    try {
        const { result } = await wasmStep(
            'Generate circuit zkspec 0',
            () => generateCircuit(0),
            ({ result }) => circuitMetrics(JSON.parse(result).circuit_data_hex)
        );
        circuitJson = JSON.parse(result);
        circuitHex = circuitJson.circuit_data_hex;
        if (!circuitHex) throw new Error('missing circuit_data_hex');
        ok('Generate circuit for zkspec 0');
    } catch (e) {
        nok(`Generate circuit for zkspec 0 — ${e.message}`);
    }

    // Test 2: Generate circuit for zkspec 1
    let circuit1Hex = '';
    try {
        const { result } = await wasmStep(
            'Generate circuit zkspec 1',
            () => generateCircuit(1),
            ({ result }) => circuitMetrics(JSON.parse(result).circuit_data_hex)
        );
        const c = JSON.parse(result);
        circuit1Hex = c.circuit_data_hex;
        if (c._zkspec?.index !== 1) throw new Error(`wrong zkspec: ${c._zkspec?.index}`);
        ok('Generate circuit for zkspec 1');
    } catch (e) {
        nok(`Generate circuit for zkspec 1 — ${e.message}`);
    }

    // Test 3: Prove with mdoc_00
    console.log('\n--- mdoc proof generation ---');

    let proof00 = null;
    try {
        const mdoc = await loadMdoc('mdoc_00.json');
        const mdocHex = bytesToHex(base64ToBytes(mdoc.mdoc_data_base64));

        const attrs = (mdoc.attributes || []).map(a => ({
            namespace: a.namespace,
            id: a.id,
            cbor_value: a.cbor_value.replace(/^0x/, ''),
        }));

        const { result } = await wasmStep(
            'Generate proof mdoc_00',
            () => generateProof({
                circuitHex,
                mdocHex,
                pkxHex: mdoc.public_key.x,
                pkyHex: mdoc.public_key.y,
                transcriptHex: mdoc.transcript.replace(/^0x/, ''),
                time: mdoc.time,
                docType: mdoc.doc_type,
                zkspecIndex: mdoc.zkspec,
                attributes: attrs,
            }),
            ({ result }) => proofMetrics(JSON.parse(result).proof_data_hex)
        );

        proof00 = JSON.parse(result);
        if (!proof00.proof_data_hex) throw new Error('missing proof_data_hex');
        ok('Generate proof with mdoc_00');
    } catch (e) {
        nok(`Generate proof with mdoc_00 — ${e.message}`);
    }

    // Test 4: Verify proof from mdoc_00
    console.log('\n--- mdoc proof verification ---');

    if (proof00) {
        try {
            const mdoc = await loadMdoc('mdoc_00.json');
            const transcriptHex = mdoc.transcript.replace(/^0x/, '');

            const attrs = (mdoc.attributes || []).map(a => ({
                namespace: a.namespace,
                id: a.id,
                cbor_value: a.cbor_value.replace(/^0x/, ''),
            }));

            const { result } = await wasmStep(
                'Verify proof mdoc_00',
                () => verifyProof({
                    circuitHex,
                    proofHex: proof00.proof_data_hex,
                    pkxHex: mdoc.public_key.x,
                    pkyHex: mdoc.public_key.y,
                    transcriptHex,
                    time: mdoc.time,
                    docType: mdoc.doc_type,
                    zkspecIndex: mdoc.zkspec,
                    attributes: attrs,
                }),
                () => verifyMetrics(circuitHex, proof00.proof_data_hex)
            );

            const vr = JSON.parse(result);
            if (!vr.result?.includes('successful')) throw new Error(`unexpected: ${result}`);
            ok('Verify proof from mdoc_00');
        } catch (e) {
            nok(`Verify proof from mdoc_00 — ${e.message}`);
        }
    }

    // Test 5: Prove and verify with mdoc_01 (same zkspec, different data)
    console.log('\n--- mdoc cross-document test ---');

    let proof01 = null;
    try {
        const mdoc = await loadMdoc('mdoc_01.json');
        const mdocHex = bytesToHex(base64ToBytes(mdoc.mdoc_data_base64));
        const transcriptHex = mdoc.transcript.replace(/^0x/, '');

        const { result } = await wasmStep(
            'Generate proof mdoc_01',
            () => generateProof({
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
            }),
            ({ result }) => proofMetrics(JSON.parse(result).proof_data_hex)
        );

        proof01 = JSON.parse(result);
        ok('Generate proof with mdoc_01');

        const { result: vr } = await wasmStep(
            'Verify proof mdoc_01',
            () => verifyProof({
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
            }),
            () => verifyMetrics(circuitHex, proof01.proof_data_hex)
        );

        const parsed = JSON.parse(vr);
        if (!parsed.result?.includes('successful')) throw new Error(`unexpected: ${vr}`);
        ok('Verify proof from mdoc_01');
    } catch (e) {
        nok(`Cross-document test — ${e.message}`);
    }

    // Test 6: Failure — mismatched zkspec
    console.log('\n--- mdoc failure cases ---');

    if (proof00 && circuit1Hex) {
        try {
            const mdoc = await loadMdoc('mdoc_00.json');
            const transcriptHex = mdoc.transcript.replace(/^0x/, '');
            await wasmStep(
                'Verify proof with wrong zkspec',
                () => verifyProof({
                    circuitHex: circuit1Hex,
                    proofHex: proof00.proof_data_hex,
                    pkxHex: mdoc.public_key.x,
                    pkyHex: mdoc.public_key.y,
                    transcriptHex,
                    time: mdoc.time,
                    docType: mdoc.doc_type,
                    zkspecIndex: mdoc.zkspec,
                    attributes: [],
                }),
                () => verifyMetrics(circuit1Hex, proof00.proof_data_hex)
            );
            nok('Verify fails with wrong zkspec — expected error, got success');
        } catch (e) {
            ok('Verify fails with wrong zkspec circuit');
        }
    }

    // Test 7: Invalid hex input
    try {
        await wasmStep(
            'Generate proof with invalid hex',
            () => generateProof({
                circuitHex: 'not-hex!',
                mdocHex: 'aa',
                pkxHex: 'aa',
                pkyHex: 'aa',
                transcriptHex: 'aa',
                time: 'now',
                docType: 'x',
                zkspecIndex: 0,
                attributes: [],
            }),
            () => 'compressed bytes: n/a (invalid input)'
        );
        nok('Invalid hex input — expected error, got success');
    } catch (e) {
        ok('Rejects invalid hex input');
    }

    // Test 8: Invalid attribute CBOR hex
    if (circuitHex) {
        try {
            const mdoc = await loadMdoc('mdoc_00.json');
            const mdocHex = bytesToHex(base64ToBytes(mdoc.mdoc_data_base64));
            await wasmStep(
                'Generate proof with invalid attrs_json cbor_value',
                () => generateProof({
                    circuitHex,
                    mdocHex,
                    pkxHex: mdoc.public_key.x,
                    pkyHex: mdoc.public_key.y,
                    transcriptHex: mdoc.transcript.replace(/^0x/, ''),
                    time: mdoc.time,
                    docType: mdoc.doc_type,
                    zkspecIndex: mdoc.zkspec,
                    attributes: [{ namespace: 'x', id: 'y', cbor_value: 'not-hex' }],
                }),
                () => circuitMetrics(circuitHex)
            );
            nok('Invalid attrs_json cbor_value — expected error, got success');
        } catch (e) {
            ok('Rejects invalid attrs_json cbor_value');
        }
    }
}

// -- summary -----------------------------------------------------------
console.log(`\n${YELLOW}=== Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC} ${YELLOW}===${NC}`);
exit(fail > 0 ? 1 : 0);
