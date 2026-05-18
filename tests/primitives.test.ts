import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  aes256GcmDecrypt,
  aes256GcmEncrypt,
  aes256GcmEncryptWithNonce,
  ed25519Sign,
  ed25519Verify,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  randomBytes,
  x25519SharedSecret
} from '../src/index.js';

describe('primitive wrappers', () => {
  it('derives the same X25519 shared secret on both sides', () => {
    const alice = generateX25519KeyPair();
    const bob = generateX25519KeyPair();

    expect(x25519SharedSecret(alice.secretKey, bob.publicKey)).toEqual(
      x25519SharedSecret(bob.secretKey, alice.publicKey)
    );
  });

  it('signs and verifies Ed25519 messages', () => {
    const keyPair = generateEd25519KeyPair();
    const message = new TextEncoder().encode('SemaFore signing fixture');
    const signature = ed25519Sign(message, keyPair.secretKey);

    expect(ed25519Verify(signature, message, keyPair.publicKey)).toBe(true);
    expect(ed25519Verify(signature, new TextEncoder().encode('tampered'), keyPair.publicKey)).toBe(false);
  });

  it('round-trips AES-256-GCM with random nonces', () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('encrypted from the Action runtime to the device');
    const encrypted = aes256GcmEncrypt(key, plaintext);

    expect(encrypted.nonce).toHaveLength(12);
    expect(aes256GcmDecrypt(key, encrypted.nonce, encrypted.ciphertext)).toEqual(plaintext);
  });

  it('rejects tampered AES-256-GCM ciphertext', () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('do not accept modified ciphertext');
    const encrypted = aes256GcmEncrypt(key, plaintext);
    const tampered = encrypted.ciphertext.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;

    expect(() => aes256GcmDecrypt(key, encrypted.nonce, tampered)).toThrow();
  });

  it('property-tests AES-256-GCM round trips', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), (input) => {
        const key = randomBytes(32);
        const nonce = randomBytes(12);
        const ciphertext = aes256GcmEncryptWithNonce(key, nonce, input);
        expect(aes256GcmDecrypt(key, nonce, ciphertext)).toEqual(input);
      }),
      { numRuns: 50 }
    );
  });
});
