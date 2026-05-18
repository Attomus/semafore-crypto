import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { assertByteLength, concatBytes, equalBytes, readUint32BE, utf8ToBytes, writeUint32BE } from './bytes.js';
import { hkdfSha256, X25519_KEY_LENGTH, x25519SharedSecret } from './primitives.js';

export const SMD1_MAGIC = new Uint8Array([0x53, 0x4d, 0x44, 0x31]);
export const SMD1_HEADER_LENGTH = 56;
export const DR_V1_BOOTSTRAP_INFO = 'SemaFore-DR-v1-init';
export const DR_V1_RATCHET_INFO = 'SemaFore-DR-v1-ratchet';
export const DR_V1_MESSAGE_KEY_MARKER = new Uint8Array([0x01]);
export const DR_V1_CHAIN_KEY_MARKER = new Uint8Array([0x02]);

export interface DrV1Header {
  readonly ratchetPublicKey: Uint8Array;
  readonly previousChainLength: number;
  readonly messageNumber: number;
  readonly nonce: Uint8Array;
}

export interface DrV1MessageKeys {
  readonly messageKey: Uint8Array;
  readonly nextChainKey: Uint8Array;
}

export interface DrV1RatchetKeys {
  readonly rootKey: Uint8Array;
  readonly chainKey: Uint8Array;
}

export function encodeDrV1Header(header: DrV1Header): Uint8Array {
  assertByteLength(header.ratchetPublicKey, X25519_KEY_LENGTH, 'DR-v1 ratchet public key');
  assertByteLength(header.nonce, 12, 'DR-v1 nonce');
  return concatBytes([
    SMD1_MAGIC,
    header.ratchetPublicKey,
    writeUint32BE(header.previousChainLength),
    writeUint32BE(header.messageNumber),
    header.nonce
  ]);
}

export function parseDrV1Header(input: Uint8Array): DrV1Header {
  if (input.length < SMD1_HEADER_LENGTH) {
    throw new RangeError(`DR-v1 frame must be at least ${SMD1_HEADER_LENGTH} bytes`);
  }
  if (!equalBytes(input.slice(0, 4), SMD1_MAGIC)) {
    throw new Error('DR-v1 header magic mismatch');
  }
  return {
    ratchetPublicKey: input.slice(4, 36),
    previousChainLength: readUint32BE(input, 36),
    messageNumber: readUint32BE(input, 40),
    nonce: input.slice(44, 56)
  };
}

export function deriveDrV1MessageKeys(chainKey: Uint8Array): DrV1MessageKeys {
  assertByteLength(chainKey, 32, 'DR-v1 chain key');
  return {
    messageKey: hmac(sha256, chainKey, DR_V1_MESSAGE_KEY_MARKER),
    nextChainKey: hmac(sha256, chainKey, DR_V1_CHAIN_KEY_MARKER)
  };
}

export function deriveDrV1BootstrapRootKey(x3dhSharedSecret: Uint8Array): Uint8Array {
  return hkdfSha256(x3dhSharedSecret, new Uint8Array(32), utf8ToBytes(DR_V1_BOOTSTRAP_INFO), 32);
}

export function deriveDrV1RatchetKeys(rootKey: Uint8Array, localRatchetSecretKey: Uint8Array, remoteRatchetPublicKey: Uint8Array): DrV1RatchetKeys {
  assertByteLength(rootKey, 32, 'DR-v1 root key');
  const dh = x25519SharedSecret(localRatchetSecretKey, remoteRatchetPublicKey);
  const output = hkdfSha256(dh, rootKey, utf8ToBytes(DR_V1_RATCHET_INFO), 64);
  return {
    rootKey: output.slice(0, 32),
    chainKey: output.slice(32, 64)
  };
}
