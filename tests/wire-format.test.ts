import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  bytesToHex,
  deriveDrV1MessageKeys,
  deriveDrV1RatchetKeys,
  encodeDrV1Header,
  encodeSmx1Envelope,
  hexToBytes,
  parseDrV1Header,
  parseSmx1Envelope
} from '../src/index.js';

interface DrV1Vector {
  readonly cases: readonly {
    readonly name: string;
    readonly initial_root_key_hex: string;
    readonly local_private_key_hex: string;
    readonly remote_public_key_hex: string;
    readonly dr_v1_header_hex: string;
    readonly initial_chain_key_hex: string;
    readonly message_key_hex: string;
    readonly next_chain_key_hex: string;
    readonly post_ratchet_root_key_hex: string;
    readonly post_ratchet_chain_key_hex: string;
  }[];
}

function vectorPath(fileName: string): string {
  return resolve(process.env.SEMAFORE_TEST_VECTORS_DIR ?? '../sf-shared-docs/docs/test-vectors', fileName);
}

function readDrV1Vector(): DrV1Vector {
  return JSON.parse(readFileSync(vectorPath('dr-v1-interop.json'), 'utf8')) as DrV1Vector;
}

describe('SMX1 wire format', () => {
  it('serializes and parses a prekey envelope with big-endian UTF-8 key-id lengths', () => {
    const envelope = {
      senderEphemeralPublicKey: new Uint8Array(32).fill(0x11),
      signedPrekeyId: 'spk-2026-05',
      oneTimePrekeyId: 'opk-0001',
      nonce: new Uint8Array(12).fill(0x22),
      ciphertext: new Uint8Array([0xaa, 0xbb, 0xcc])
    };

    const encoded = encodeSmx1Envelope(envelope);
    expect(bytesToHex(encoded.slice(0, 5))).toBe('534d583101');
    expect(bytesToHex(encoded.slice(37, 39))).toBe('000b');
    const parsed = parseSmx1Envelope(encoded);

    expect(parsed.signedPrekeyId).toBe(envelope.signedPrekeyId);
    expect(parsed.oneTimePrekeyId).toBe(envelope.oneTimePrekeyId);
    expect(parsed.senderEphemeralPublicKey).toEqual(envelope.senderEphemeralPublicKey);
    expect(parsed.nonce).toEqual(envelope.nonce);
    expect(parsed.ciphertext).toEqual(envelope.ciphertext);
  });

  it('serializes an absent OPK as clear flags plus zero-length OPK id', () => {
    const encoded = encodeSmx1Envelope({
      senderEphemeralPublicKey: new Uint8Array(32).fill(0x33),
      signedPrekeyId: 'spk-only',
      nonce: new Uint8Array(12).fill(0x44),
      ciphertext: new Uint8Array([0xdd])
    });

    expect(bytesToHex(encoded.slice(0, 5))).toBe('534d583100');
    expect(parseSmx1Envelope(encoded).oneTimePrekeyId).toBeUndefined();
  });
});

describe('DR-v1 conformance vectors', () => {
  it('loads the shared DR-v1 vector file', () => {
    expect(existsSync(vectorPath('dr-v1-interop.json'))).toBe(true);
  });

  for (const testCase of readDrV1Vector().cases) {
    it(`matches ${testCase.name}`, () => {
      const parsedHeader = parseDrV1Header(hexToBytes(testCase.dr_v1_header_hex));
      expect(bytesToHex(encodeDrV1Header(parsedHeader))).toBe(testCase.dr_v1_header_hex);

      const messageKeys = deriveDrV1MessageKeys(hexToBytes(testCase.initial_chain_key_hex));
      expect(bytesToHex(messageKeys.messageKey)).toBe(testCase.message_key_hex);
      expect(bytesToHex(messageKeys.nextChainKey)).toBe(testCase.next_chain_key_hex);

      const ratchetKeys = deriveDrV1RatchetKeys(
        hexToBytes(testCase.initial_root_key_hex),
        hexToBytes(testCase.local_private_key_hex),
        hexToBytes(testCase.remote_public_key_hex)
      );
      expect(bytesToHex(ratchetKeys.rootKey)).toBe(testCase.post_ratchet_root_key_hex);
      expect(bytesToHex(ratchetKeys.chainKey)).toBe(testCase.post_ratchet_chain_key_hex);
    });
  }
});
