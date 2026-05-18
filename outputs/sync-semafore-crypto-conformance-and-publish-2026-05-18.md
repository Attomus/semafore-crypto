# SemaFore Crypto Conformance and Publish Sync - 2026-05-18

## Status

`@attomus/semafore-crypto` is ready for review toward `v1.0.0`.

## Completed

- Wired the canonical X3DH SMX1 vector from `sf-shared-docs` commit `5ac5899` into the conformance suite.
- Covered both vector cases: OPK-present and OPK-absent.
- Asserted sender DH outputs, HKDF IKM, HKDF output, and serialized SMX1 header bytes.
- Added support for signed-prekey signature messages so the library can verify the Android vector's DER-encoded signed-prekey signature input.
- Added deterministic nonce injection for conformance tests without changing the default random-nonce runtime path.
- Bumped package metadata to `1.0.0` and added `CHANGELOG.md`.

## Verification

- `npm run test -- tests/wire-format.test.ts` passed locally after wiring the vector.
- Full verification, current-tree secret scan, package dry-run, PR readiness, tag, and npm publish remain to be completed after the final local sweep and PR merge.

## Publish Notes

- After PR #6 merges to `main`, tag `v1.0.0` and publish `@attomus/semafore-crypto@1.0.0`.
- If npm auth or GitHub Actions publishing is still blocked, hold at the ready-for-review PR state and coordinate operator credentials before publishing.
