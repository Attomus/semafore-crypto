import {
  assertByteLength,
  assertMinByteLength,
  concatBytes,
  equalBytes,
  readLengthPrefixedUtf8,
  writeLengthPrefixedUtf8
} from './bytes.js';
import { AES_GCM_NONCE_LENGTH, X25519_KEY_LENGTH } from './primitives.js';

export const SMX1_MAGIC = new Uint8Array([0x53, 0x4d, 0x58, 0x31]);
export const SMX1_FLAG_OPK_USED = 0x01;
export const SMX1_MIN_HEADER_LENGTH = 4 + 1 + X25519_KEY_LENGTH + 2 + 2 + AES_GCM_NONCE_LENGTH;

export interface Smx1Envelope {
  readonly senderEphemeralPublicKey: Uint8Array;
  readonly signedPrekeyId: string;
  readonly oneTimePrekeyId?: string;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export interface ParsedSmx1Envelope extends Smx1Envelope {
  readonly flags: number;
  readonly headerBytes: Uint8Array;
}

export function encodeSmx1Envelope(envelope: Smx1Envelope): Uint8Array {
  assertByteLength(envelope.senderEphemeralPublicKey, X25519_KEY_LENGTH, 'SMX1 sender ephemeral public key');
  assertByteLength(envelope.nonce, AES_GCM_NONCE_LENGTH, 'SMX1 nonce');
  const opkId = envelope.oneTimePrekeyId;
  const flags = opkId === undefined ? 0x00 : SMX1_FLAG_OPK_USED;
  return concatBytes([
    SMX1_MAGIC,
    new Uint8Array([flags]),
    envelope.senderEphemeralPublicKey,
    writeLengthPrefixedUtf8(envelope.signedPrekeyId, 'SMX1 signed prekey id'),
    writeLengthPrefixedUtf8(opkId ?? '', 'SMX1 one-time prekey id'),
    envelope.nonce,
    envelope.ciphertext
  ]);
}

export function parseSmx1Envelope(input: Uint8Array): ParsedSmx1Envelope {
  assertMinByteLength(input, SMX1_MIN_HEADER_LENGTH, 'SMX1 envelope');
  if (!equalBytes(input.slice(0, 4), SMX1_MAGIC)) {
    throw new Error('SMX1 envelope magic mismatch');
  }
  const flags = input[4] ?? 0;
  if ((flags & ~SMX1_FLAG_OPK_USED) !== 0) {
    throw new Error('SMX1 envelope contains unsupported flags');
  }
  const senderEphemeralPublicKey = input.slice(5, 5 + X25519_KEY_LENGTH);
  let offset = 5 + X25519_KEY_LENGTH;
  const spk = readLengthPrefixedUtf8(input, offset);
  offset = spk.nextOffset;
  const opk = readLengthPrefixedUtf8(input, offset);
  offset = opk.nextOffset;
  const opkWasUsed = (flags & SMX1_FLAG_OPK_USED) === SMX1_FLAG_OPK_USED;
  if (!opkWasUsed && opk.value.length !== 0) {
    throw new Error('SMX1 OPK id must be empty when OPK flag is clear');
  }
  if (opkWasUsed && opk.value.length === 0) {
    throw new Error('SMX1 OPK id is required when OPK flag is set');
  }
  if (offset + AES_GCM_NONCE_LENGTH > input.length) {
    throw new RangeError('SMX1 nonce is truncated');
  }
  const nonce = input.slice(offset, offset + AES_GCM_NONCE_LENGTH);
  offset += AES_GCM_NONCE_LENGTH;
  return {
    flags,
    senderEphemeralPublicKey,
    signedPrekeyId: spk.value,
    oneTimePrekeyId: opkWasUsed ? opk.value : undefined,
    nonce,
    ciphertext: input.slice(offset),
    headerBytes: input.slice(0, offset)
  };
}
