# SemaFore Crypto Conformance and Publish Sync - 2026-05-27

## Status

`@attomus/semafore-crypto` is release-prepped for `v1.0.0`.

Publish remains blocked on npm credentials. The repo has no `NPM_TOKEN` secret,
and local npm auth is absent (`npm whoami` returns `ENEEDAUTH`). The npm
registry currently returns `E404` for `@attomus/semafore-crypto`, so no public
package version is live yet.

## Completed

- Wired the canonical X3DH SMX1 vector from `sf-shared-docs` commit `5ac5899` into the conformance suite.
- Covered both vector cases: OPK-present and OPK-absent.
- Asserted sender DH outputs, HKDF IKM, HKDF output, and serialized SMX1 header bytes.
- Added support for signed-prekey signature messages so the library can verify the Android vector's DER-encoded signed-prekey signature input.
- Added deterministic nonce injection for conformance tests without changing the default random-nonce runtime path.
- Confirmed PR #6 is merged and no longer draft.
- Bumped package metadata to `1.0.0` and refreshed `CHANGELOG.md`.

## Verification

- `npm run verify` passed locally.
- `gitleaks detect --no-banner -v` passed locally.
- `npm pack --dry-run --json` passed locally at package version `1.0.0`;
  tarball size was 35096 bytes.
- PR #6 CI passed: run `26061523766`.
- GitHub Actions is enabled for `Attomus/semafore-crypto`.

## Publish Notes

- Add an npm automation token as GitHub secret `NPM_TOKEN` on `Attomus/semafore-crypto`.
- Tag `v1.0.0` after the release-prep PR merges to `main`.
- Let the tag workflow publish, or run `npm publish --access public` locally after `npm adduser`.
- Confirm `npm view @attomus/semafore-crypto version` returns `1.0.0`.
