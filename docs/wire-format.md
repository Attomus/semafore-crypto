# SemaFore Crypto Wire Formats

This document summarizes the wire layouts implemented by
`@attomus/semafore-crypto`.

## SMX1

SMX1 is the SemaFore X3DH v1 prekey envelope. It appears on first contact when a
sender needs the recipient to reconstruct the initial shared secret.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic `53 4D 58 31` (`SMX1`) |
| 4 | 1 | Flags: `01` when an OPK was used, otherwise `00` |
| 5 | 32 | Sender ephemeral X25519 public key `EK_A` |
| 37 | 2 | SPK `key_id` length, big-endian uint16 |
| 39 | L1 | SPK `key_id`, UTF-8 |
| 39+L1 | 2 | OPK `key_id` length, big-endian uint16; zero when no OPK was used |
| 41+L1 | L2 | OPK `key_id`, UTF-8 when present |
| 41+L1+L2 | 12 | AES-GCM nonce |
| 53+L1+L2 | variable | AES-GCM ciphertext plus 16-byte tag |

Example prefix for an OPK-backed envelope:

```text
53 4d 58 31 01 ...
```

### SMX1 header integrity

SMX1 does not currently pass its serialized header bytes as AES-GCM additional
authenticated data. Header integrity instead rests on the X3DH agreement:

- the sender ephemeral public key feeds the receiver-side DH2/DH3/DH4 inputs;
- the signed-prekey id selects the receiver signed prekey secret used for DH1
  and DH3;
- the one-time-prekey id, when present, selects the receiver OPK secret used for
  DH4;
- the nonce is the AES-GCM nonce for the derived first-message key.

Tampering with any of those fields makes the receiver derive a different
message key or use a different GCM nonce, so decryption fails the GCM
authentication check and yields no plaintext. The protocol tests include
explicit SMX1 tamper cases for `senderEphemeralPublicKey`, `signedPrekeyId`,
`oneTimePrekeyId`, and `nonce` to lock this implicit-authentication property
against regression.

OPK lookup must be read-only. Callers should consume/burn the referenced OPK
only after SMX1 decryption succeeds; a tampered `oneTimePrekeyId` that points at
another valid OPK must not burn that unrelated OPK before the GCM check fails.

The next versioned first-contact frame should bind the SMX1-equivalent header
as explicit AES-GCM AAD for consistency with SMD1. That is a breaking
wire-format change and must land with a version discriminator and cross-platform
conformance vectors.

## SMD1 / DR-v1

SMD1 is the SemaFore Double Ratchet v1 frame header. The server stores and
relays the header and ciphertext as opaque bytes.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic `53 4D 44 31` (`SMD1`) |
| 4 | 32 | Sender current ratchet public key |
| 36 | 4 | Previous-chain message count `PN`, big-endian uint32 |
| 40 | 4 | Message number `N`, big-endian uint32 |
| 44 | 12 | AES-GCM nonce |
| 56 | variable | AES-GCM ciphertext plus 16-byte tag |

DR-v1 derivation constants:

| Constant | Value |
|---|---|
| Bootstrap HKDF info | `SemaFore-DR-v1-init` |
| Ratchet HKDF info | `SemaFore-DR-v1-ratchet` |
| Message-key HMAC marker | `01` |
| Chain-key HMAC marker | `02` |

The high-level session API treats the SMX1 first-contact message as message
number zero of the initial sending chain. Follow-up traffic uses SMD1 frames.
SMD1 AES-GCM encryption authenticates the 56-byte header as additional data so
ratchet key, previous-chain count, message number, and nonce tampering fails
decryption.

Skipped message keys are retained in-memory only and are bounded by the
session's `maxSkippedMessageKeys` setting, which defaults to 64. Callers remain
responsible for durable session persistence between process runs.

## Conformance

The test suite covers the checked-in SemaFore vectors:

- `dr-v1-interop.json`
- `x3dh-prekey-v1.json`, pinned from `sf-shared-docs` commit `5ac5899`

The SMX1 vector covers both OPK-present and OPK-absent first-contact flows and
asserts sender DH outputs, HKDF input material, HKDF output, and serialized
SMX1 header bytes.
