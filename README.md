# @attomus/semafore-crypto

TypeScript implementation of SemaFore cryptographic wire-format primitives.

This package is intended for SemaFore integration runtimes that must encrypt
message content before it leaves the caller-controlled environment. It does not
perform network calls, persistence, service-token handling, or aggregation.

## Status

Early implementation. The primitive layer and wire serializers are present, and
DR-v1 conformance tests consume the shared SemaFore vectors. The X3DH/SMX1
state-machine path is intentionally gated until the canonical
`x3dh-prekey-v1.json` vector exists and the X3DH HKDF parameter discrepancy
between the iOS and Android planning records is resolved.

## Install

```sh
npm install @attomus/semafore-crypto
```

## Quick Start

```ts
import {
  aes256GcmDecrypt,
  aes256GcmEncrypt,
  generateX25519KeyPair,
  x25519SharedSecret
} from '@attomus/semafore-crypto';

const alice = generateX25519KeyPair();
const bob = generateX25519KeyPair();
const shared = x25519SharedSecret(alice.secretKey, bob.publicKey);

const encrypted = aes256GcmEncrypt(shared, new TextEncoder().encode('Hello SemaFore'));
const plaintext = aes256GcmDecrypt(shared, encrypted.nonce, encrypted.ciphertext);
```

## Security Model

- AES-256-GCM uses a fresh random 12-byte nonce for each high-level encrypt call.
- X25519, Ed25519, HKDF-SHA256, and AES-GCM are provided by the audited
  `@noble/*` packages.
- The library treats SemaFore wire formats as compatibility contracts. Any
  change to SMX1 or SMD1 is a breaking protocol change and must be versioned.
- Callers own storage and state persistence. Do not persist private keys or
  ratchet state in plaintext.

## Wire Format Conformance

The test suite reads shared vectors from
`sf-shared-docs/docs/test-vectors/*.json`. In CI, the shared-docs repo is
checked out next to this repo and `SEMAFORE_TEST_VECTORS_DIR` points at that
directory.

The current DR-v1 vector file is:

- `dr-v1-interop.json`

The missing prep vector is:

- `x3dh-prekey-v1.json`

## Responsible Disclosure

Please report security issues privately. See [SECURITY.md](./SECURITY.md).

## License

Apache-2.0.
