# Changelog

## 0.1.0 - 2026-05-18

- Added sender and receiver SMX1 first-contact session support.
- Added SMD1 Double Ratchet send/receive support with skipped-message-key handling.
- Added byte-level conformance coverage for DR-v1 and X3DH SMX1 vectors, including OPK-present and OPK-absent cases from `sf-shared-docs` commit `5ac5899`.
- Renamed session identity inputs to `localIdentity` and `peerIdentityPublicKey` before the public API is frozen.
- Published the first stable package surface for downstream GitHub Action integration.
