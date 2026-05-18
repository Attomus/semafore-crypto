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

## Open Conformance Item

`x3dh-prekey-v1.json` is still required before the SMX1 state machine can claim
cross-language wire compatibility. The iOS plan and Android plan currently
disagree on X3DH HKDF parameter placement: iOS records info
`SemaFore-X3DH-v1`, while an Android note records salt `SemaForeX3DHv1` with
empty info. The library exposes both parameter helpers but defaults the
high-level session API to the iOS Phase 3 parameters until the shared vector
resolves the canonical choice.
