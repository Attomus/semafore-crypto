# @attomus/semafore-crypto

TypeScript implementation of SemaFore cryptographic wire-format primitives.

This package is intended for SemaFore integration runtimes that must encrypt
message content before it leaves the caller-controlled environment. It does not
perform network calls, persistence, service-token handling, or aggregation.

## Status

Early implementation. The primitive layer, SMX1/SMD1 wire serializers, X3DH
bootstrap helpers, and in-memory protocol session state machine are present.
DR-v1 conformance tests consume the shared SemaFore vectors. The X3DH/SMX1 path
has local round-trip coverage, but cannot be declared cross-language
wire-compatible until the canonical `x3dh-prekey-v1.json` vector exists and the
X3DH HKDF parameter discrepancy between the iOS and Android planning records is
resolved.

## Install

```sh
npm install @attomus/semafore-crypto
```

## Quick Start

```ts
import {
  decryptMessage,
  encryptMessage,
  generateEd25519KeyPair,
  generateIdentityKeyPair,
  generateOneTimePrekey,
  generateSignedPrekey,
  initReceiverSession,
  initSenderSession
} from '@attomus/semafore-crypto';

const aliceIdentity = generateIdentityKeyPair();
const bobIdentity = generateIdentityKeyPair();
const bobSigning = generateEd25519KeyPair();
const bobSpk = generateSignedPrekey(bobSigning.secretKey, 'spk-current');
const bobOpk = generateOneTimePrekey('opk-001');

const aliceSession = initSenderSession({
  myIdentity: aliceIdentity,
  recipientBundle: {
    identityAgreementKey: bobIdentity.publicKey,
    identitySigningKey: bobSigning.publicKey,
    signedPrekey: bobSpk,
    oneTimePrekey: bobOpk
  }
});
const firstEnvelope = encryptMessage(aliceSession, 'Hello SemaFore');

const { session: bobSession } = initReceiverSession({
  myIdentity: bobIdentity,
  senderIdentityPublicKey: aliceIdentity.publicKey,
  envelope: firstEnvelope,
  signedPrekeyLookup: () => bobSpk,
  oneTimePrekeyLookup: () => bobOpk
});
const plaintext = decryptMessage(bobSession, firstEnvelope);
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
