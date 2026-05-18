# SemaFore Crypto Conformance and Publish Sync - 2026-05-18

## Status

`@attomus/semafore-crypto` is tagged at `v1.0.0` on `main`.

Publish is blocked on npm credentials: the tag workflow reached `npm publish`,
but `NODE_AUTH_TOKEN` was empty because the repo has no `NPM_TOKEN` secret.
Local npm auth is also absent (`npm whoami` returns `ENEEDAUTH`).

## Completed

- Wired the canonical X3DH SMX1 vector from `sf-shared-docs` commit `5ac5899` into the conformance suite.
- Covered both vector cases: OPK-present and OPK-absent.
- Asserted sender DH outputs, HKDF IKM, HKDF output, and serialized SMX1 header bytes.
- Added support for signed-prekey signature messages so the library can verify the Android vector's DER-encoded signed-prekey signature input.
- Added deterministic nonce injection for conformance tests without changing the default random-nonce runtime path.
- Bumped package metadata to `1.0.0` and added `CHANGELOG.md`.
- Merged PR #6 to `dev`, PR #7 to `staging`, and PR #8 to `main`.
- Tagged `v1.0.0` at main commit `c811e9e`.

## Verification

- `npm run verify` passed locally.
- `gitleaks dir --no-banner -v .` passed locally.
- `npm publish --dry-run --access public` passed locally.
- PR #6 CI passed: run `26061523766`.
- `dev` CI passed: run `26061576430`.
- `staging` CI passed: run `26061619594`.
- `main` CI passed: run `26061656977`.
- Tag CI passed through build/test, then failed at publish because `NPM_TOKEN` is not configured: run `26061695164`.

## Publish Notes

- Add an npm automation token as GitHub secret `NPM_TOKEN` on `Attomus/semafore-crypto`.
- Re-run failed tag workflow `26061695164`, or run `npm publish --access public` locally after `npm adduser`.
- Confirm `npm view @attomus/semafore-crypto version` returns `1.0.0`.
