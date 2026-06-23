# @attomus/semafore-crypto

TypeScript implementation of SemaFore's end-to-end encrypted messaging wire
format.

This package is for integration runtimes that need to encrypt SemaFore message
content before it leaves the caller-controlled environment. It contains the
cryptographic and wire-format layer only: no network calls, no service-token
handling, no storage, and no aggregation.

## Status

Current package line is `1.0.1`. The cryptographic wire-format surface is covered
by byte-level conformance vectors, but the surrounding SemaFore integration
surface is still in active development while the GitHub Action moves toward
Marketplace readiness.

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

After the npm release is published:

```sh
npm install @attomus/semafore-crypto
```

## Quick Start

```ts
import {
  generateIdentityKeyPair,
  generateEd25519KeyPair,
  generateSignedPrekey,
  generateOneTimePrekey,
  initReceiverSession,
  initSenderSession,
  encryptMessage,
  decryptMessage
} from '@attomus/semafore-crypto';

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

// Long-lived identity keys: X25519 for ECDH, Ed25519 for signatures.
const aliceIdentity = generateIdentityKeyPair();
const bobIdentity = generateIdentityKeyPair();
const bobSigning = generateEd25519KeyPair();

// Bob publishes a signed prekey and one-time prekeys. Alice fetches them as a bundle.
const bobSpk = generateSignedPrekey(bobSigning.secretKey, 'spk-current');
const bobOpk = generateOneTimePrekey('opk-001');

const aliceSession = initSenderSession({
  localIdentity: aliceIdentity,
  recipientBundle: {
    identityAgreementKey: bobIdentity.publicKey,
    identitySigningKey: bobSigning.publicKey,
    signedPrekey: bobSpk,
    oneTimePrekey: bobOpk
  }
});

// First message: carries the X3DH bootstrap. Later messages on this session
// use the Double Ratchet continuation path.
const firstEnvelope = encryptMessage(aliceSession, 'Hello SemaFore');

// Bob's prekey lookups typically hit on-device storage; stubbed here.
const { session: bobSession } = initReceiverSession({
  localIdentity: bobIdentity,
  peerIdentityPublicKey: aliceIdentity.publicKey,
  envelope: firstEnvelope,
  signedPrekeyLookup: () => bobSpk,
  oneTimePrekeyLookup: () => bobOpk
});

const plaintext = decryptMessage(bobSession, firstEnvelope);
console.log(decode(plaintext)); // 'Hello SemaFore'

// Second message: same session, now continuing under Double Ratchet.
const secondEnvelope = encryptMessage(aliceSession, 'and again');
console.log(decode(decryptMessage(bobSession, secondEnvelope))); // 'and again'
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
