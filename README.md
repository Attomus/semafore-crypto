# @attomus/semafore-crypto

TypeScript implementation of SemaFore's end-to-end encrypted messaging wire
format.

This package is for integration runtimes that need to encrypt SemaFore message
content before it leaves the caller-controlled environment. It contains the
cryptographic and wire-format layer only: no network calls, no service-token
handling, no storage, and no aggregation.

## Status

Early public release. The package is published as `0.1.0`, but the surrounding
SemaFore integration surface is still in active development and the API may
change before the GitHub Action reaches Marketplace readiness.

Implemented today:

- X25519 identity and ratchet keys
- Ed25519 signed-prekey validation
- AES-256-GCM payload encryption
- HKDF-SHA256 key derivation
- X3DH sender and receiver bootstrap helpers
- SMX1 first-contact envelopes
- SMD1 Double Ratchet follow-up messages
- bounded skipped-message-key handling
- byte-level conformance tests for DR-v1 and X3DH/SMX1 vectors

The implementation is wire-compatible with the current SemaFore iOS Swift and
Android Kotlin clients for the checked-in conformance vectors, including
OPK-present and OPK-absent SMX1 cases.

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

## Wire Formats

SemaFore currently uses two message envelope formats:

- **SMX1**: first-contact X3DH prekey envelope.
- **SMD1**: Double Ratchet message envelope after session bootstrap.

The wire layout is documented in [docs/wire-format.md](./docs/wire-format.md).
Changing either format is a breaking protocol change.

## Conformance

The test suite includes pinned SemaFore vectors:

- `dr-v1-interop.json`
- `x3dh-prekey-v1.json`

The X3DH/SMX1 vectors were extracted from the Android implementation and cover
both one-time-prekey-present and one-time-prekey-absent first-contact flows.

Run the full local check with:

```sh
npm run verify
```

## Security Model

- Message plaintext is encrypted before it leaves the caller's runtime.
- AES-256-GCM uses a fresh random 12-byte nonce for each encryption.
- X25519, Ed25519, HKDF-SHA256, and AES-GCM are implemented using the
  `@noble/*` packages.
- Callers own key storage, ratchet-state persistence, service-token handling,
  recipient lookup, and transport.
- Private keys and ratchet state must not be stored in plaintext by callers.

## Responsible Disclosure

Please report security issues privately. See [SECURITY.md](./SECURITY.md).

## License

Apache-2.0.
