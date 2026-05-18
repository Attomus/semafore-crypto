export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError('random byte length must be a non-negative integer');
  }
  const cryptoProvider = globalThis.crypto;
  if (!cryptoProvider?.getRandomValues) {
    throw new Error('crypto.getRandomValues is required');
  }
  const output = new Uint8Array(length);
  cryptoProvider.getRandomValues(output);
  return output;
}
