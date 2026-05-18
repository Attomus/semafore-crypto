const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function utf8ToBytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function bytesToUtf8(value: Uint8Array): string {
  return textDecoder.decode(value);
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function assertByteLength(value: Uint8Array, length: number, name: string): void {
  if (value.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes; got ${value.length}`);
  }
}

export function assertMinByteLength(value: Uint8Array, length: number, name: string): void {
  if (value.length < length) {
    throw new RangeError(`${name} must be at least ${length} bytes; got ${value.length}`);
  }
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= byteAt(left, index) ^ byteAt(right, index);
  }
  return diff === 0;
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0) {
    throw new RangeError('hex input must have an even number of characters');
  }
  if (!/^[0-9a-fA-F]*$/.test(value)) {
    throw new RangeError('hex input contains non-hex characters');
  }
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

export function readUint32BE(value: Uint8Array, offset: number): number {
  if (offset + 4 > value.length) {
    throw new RangeError('uint32 read exceeds input length');
  }
  return (
    (byteAt(value, offset) << 24) |
    (byteAt(value, offset + 1) << 16) |
    (byteAt(value, offset + 2) << 8) |
    byteAt(value, offset + 3)
  ) >>> 0;
}

export function writeUint16BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError('uint16 value is out of range');
  }
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

export function writeUint32BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError('uint32 value is out of range');
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ]);
}

export function readLengthPrefixedUtf8(input: Uint8Array, offset: number): { value: string; nextOffset: number } {
  if (offset + 2 > input.length) {
    throw new RangeError('length-prefixed string is truncated before length');
  }
  const length = (byteAt(input, offset) << 8) | byteAt(input, offset + 1);
  const start = offset + 2;
  const end = start + length;
  if (end > input.length) {
    throw new RangeError('length-prefixed string is truncated before value');
  }
  return {
    value: bytesToUtf8(input.slice(start, end)),
    nextOffset: end
  };
}

export function byteAt(value: Uint8Array, offset: number): number {
  const byte = value[offset];
  if (byte === undefined) {
    throw new RangeError('byte offset exceeds input length');
  }
  return byte;
}

export function writeLengthPrefixedUtf8(value: string, name: string): Uint8Array {
  const bytes = utf8ToBytes(value);
  if (bytes.length > 0xffff) {
    throw new RangeError(`${name} is too long for uint16 length prefix`);
  }
  return concatBytes([writeUint16BE(bytes.length), bytes]);
}
