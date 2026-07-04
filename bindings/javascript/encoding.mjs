/**
 * Encoding helpers (zenroom pattern).
 * All binary ↔ hex conversions using lowercase hex.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function isHex(value) {
    return typeof value === 'string' && value.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(value);
}

export function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
    if (!isHex(hex)) throw new Error('invalid hex string');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

export function utf8ToHex(str) {
    return bytesToHex(encoder.encode(str));
}

export function hexToUtf8(hex) {
    return decoder.decode(hexToBytes(hex));
}
