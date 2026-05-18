import { gcm } from '@noble/ciphers/aes.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { assertByteLength } from './bytes.js';
import { randomBytes } from './random.js';

export const AES_256_GCM_KEY_LENGTH = 32;
export const AES_GCM_NONCE_LENGTH = 12;
export const X25519_KEY_LENGTH = 32;
export const ED25519_PUBLIC_KEY_LENGTH = 32;
export const ED25519_SECRET_KEY_LENGTH = 32;
export const ED25519_SIGNATURE_LENGTH = 64;

export interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface AesGcmEncrypted {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export function generateX25519KeyPair(): KeyPair {
  const { publicKey, secretKey } = x25519.keygen();
  return { publicKey, secretKey };
}

export function x25519PublicKey(secretKey: Uint8Array): Uint8Array {
  assertByteLength(secretKey, X25519_KEY_LENGTH, 'X25519 secret key');
  return x25519.getPublicKey(secretKey);
}

export function x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  assertByteLength(secretKey, X25519_KEY_LENGTH, 'X25519 secret key');
  assertByteLength(peerPublicKey, X25519_KEY_LENGTH, 'X25519 peer public key');
  return x25519.getSharedSecret(secretKey, peerPublicKey);
}

export function generateEd25519KeyPair(): KeyPair {
  const { publicKey, secretKey } = ed25519.keygen();
  return { publicKey, secretKey };
}

export function ed25519PublicKey(secretKey: Uint8Array): Uint8Array {
  assertByteLength(secretKey, ED25519_SECRET_KEY_LENGTH, 'Ed25519 secret key');
  return ed25519.getPublicKey(secretKey);
}

export function ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  assertByteLength(secretKey, ED25519_SECRET_KEY_LENGTH, 'Ed25519 secret key');
  return ed25519.sign(message, secretKey);
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  assertByteLength(signature, ED25519_SIGNATURE_LENGTH, 'Ed25519 signature');
  assertByteLength(publicKey, ED25519_PUBLIC_KEY_LENGTH, 'Ed25519 public key');
  return ed25519.verify(signature, message, publicKey);
}

export function hkdfSha256(inputKeyMaterial: Uint8Array, salt: Uint8Array | undefined, info: Uint8Array | undefined, length: number): Uint8Array {
  return hkdf(sha256, inputKeyMaterial, salt, info, length);
}

export function aes256GcmEncrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): AesGcmEncrypted {
  assertByteLength(key, AES_256_GCM_KEY_LENGTH, 'AES-256-GCM key');
  const nonce = randomBytes(AES_GCM_NONCE_LENGTH);
  return {
    nonce,
    ciphertext: gcm(key, nonce, aad).encrypt(plaintext)
  };
}

export function aes256GcmEncryptWithNonce(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
  assertByteLength(key, AES_256_GCM_KEY_LENGTH, 'AES-256-GCM key');
  assertByteLength(nonce, AES_GCM_NONCE_LENGTH, 'AES-GCM nonce');
  return gcm(key, nonce, aad).encrypt(plaintext);
}

export function aes256GcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
  assertByteLength(key, AES_256_GCM_KEY_LENGTH, 'AES-256-GCM key');
  assertByteLength(nonce, AES_GCM_NONCE_LENGTH, 'AES-GCM nonce');
  return gcm(key, nonce, aad).decrypt(ciphertext);
}
