import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  bytesToHex,
  canonicalX3dhKdfParameters,
  deriveX3dhSenderMaterial,
  deriveDrV1MessageKeys,
  deriveDrV1RatchetKeys,
  encodeDrV1Header,
  encodeSmx1Envelope,
  hexToBytes,
  initSenderSession,
  encryptMessage,
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

interface X3dhPrekeyVector {
  readonly cases: readonly X3dhPrekeyCase[];
}

interface X3dhPrekeyCase {
  readonly name: string;
  readonly sender: {
    readonly identity_key_priv_hex: string;
    readonly ephemeral_key_priv_hex: string;
    readonly ephemeral_key_pub_hex: string;
  };
  readonly recipient: {
    readonly identity_signing_pub_hex: string;
    readonly identity_key_pub_hex: string;
    readonly signed_prekey_id: string;
    readonly signed_prekey_pub_hex: string;
    readonly signed_prekey_pub_der_hex: string;
    readonly signed_prekey_signature_hex: string;
    readonly opk_id?: string;
    readonly opk_pub_hex?: string;
  };
  readonly expected_dh_outputs: {
    readonly dh1_hex: string;
    readonly dh2_hex: string;
    readonly dh3_hex: string;
    readonly dh4_hex?: string;
  };
  readonly expected_hkdf_ikm_hex: string;
  readonly expected_hkdf_output_hex: string;
  readonly expected_smx1_header_hex: string;
  readonly expected_initial_dr_root_key_hex: string;
}

function vectorPath(fileName: string): string {
  return resolve(process.env.SEMAFORE_TEST_VECTORS_DIR ?? '../sf-shared-docs/docs/test-vectors', fileName);
}

function pinnedVectorPath(fileName: string): string {
  return resolve('tests/vectors', fileName);
}

function readDrV1Vector(): DrV1Vector {
  return JSON.parse(readFileSync(vectorPath('dr-v1-interop.json'), 'utf8')) as DrV1Vector;
}

function readX3dhPrekeyVector(): X3dhPrekeyVector {
  return JSON.parse(readFileSync(pinnedVectorPath('x3dh-prekey-v1.json'), 'utf8')) as X3dhPrekeyVector;
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

describe('X3DH SMX1 conformance vectors', () => {
  it('loads the shared X3DH SMX1 vector file pinned from sf-shared-docs main 5ac5899', () => {
    expect(existsSync(pinnedVectorPath('x3dh-prekey-v1.json'))).toBe(true);
  });

  for (const testCase of readX3dhPrekeyVector().cases) {
    it(`matches ${testCase.name}`, () => {
      const kdf = canonicalX3dhKdfParameters();
      const recipientBundle = {
        identityAgreementKey: hexToBytes(testCase.recipient.identity_key_pub_hex),
        identitySigningKey: hexToBytes(testCase.recipient.identity_signing_pub_hex),
        signedPrekey: {
          keyId: testCase.recipient.signed_prekey_id,
          publicKey: hexToBytes(testCase.recipient.signed_prekey_pub_hex),
          signature: hexToBytes(testCase.recipient.signed_prekey_signature_hex),
          signatureMessage: hexToBytes(testCase.recipient.signed_prekey_pub_der_hex)
        },
        oneTimePrekey:
          testCase.recipient.opk_id === undefined ||
          testCase.recipient.opk_pub_hex === undefined
            ? undefined
            : {
                keyId: testCase.recipient.opk_id,
                publicKey: hexToBytes(testCase.recipient.opk_pub_hex)
              }
      };

      const material = deriveX3dhSenderMaterial({
        senderIdentitySecretKey: hexToBytes(testCase.sender.identity_key_priv_hex),
        senderEphemeralSecretKey: hexToBytes(testCase.sender.ephemeral_key_priv_hex),
        recipientBundle,
        kdf
      });

      expect(bytesToHex(material.dh1)).toBe(testCase.expected_dh_outputs.dh1_hex);
      expect(bytesToHex(material.dh2)).toBe(testCase.expected_dh_outputs.dh2_hex);
      expect(bytesToHex(material.dh3)).toBe(testCase.expected_dh_outputs.dh3_hex);
      expect(material.dh4 === undefined ? undefined : bytesToHex(material.dh4)).toBe(
        testCase.expected_dh_outputs.dh4_hex
      );
      expect(bytesToHex(material.inputKeyMaterial)).toBe(testCase.expected_hkdf_ikm_hex);
      expect(bytesToHex(material.sharedSecret)).toBe(testCase.expected_hkdf_output_hex);
      expect(bytesToHex(material.sharedSecret)).toBe(testCase.expected_initial_dr_root_key_hex);

      const senderSession = initSenderSession({
        localIdentity: {
          publicKey: new Uint8Array(32),
          secretKey: hexToBytes(testCase.sender.identity_key_priv_hex)
        },
        recipientBundle,
        ephemeralKeyPair: {
          publicKey: hexToBytes(testCase.sender.ephemeral_key_pub_hex),
          secretKey: hexToBytes(testCase.sender.ephemeral_key_priv_hex)
        },
        kdf,
        randomBytes: (length) => {
          expect(length).toBe(12);
          return hexToBytes(testCase.expected_smx1_header_hex.slice(-24));
        }
      });
      const envelope = encryptMessage(senderSession, new Uint8Array());

      expect(envelope.kind).toBe('smx1');
      expect(bytesToHex(envelope.headerBytes)).toBe(testCase.expected_smx1_header_hex);
    });
  }
});
