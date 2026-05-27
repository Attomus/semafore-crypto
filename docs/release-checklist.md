# Release Checklist

Before tagging a package release:

- Confirm `package.json` and `package-lock.json` carry the intended version.
- Update `CHANGELOG.md` for the release.
- Review `README.md`, especially the Status and Install sections, so the npm
  package page will not ship stale release-candidate or unpublished wording.
- Run `npm run verify`.
- Run `npm pack --dry-run --json` and check the packed file list.
- Confirm the release workflow publishes through npm Trusted Publishing rather
  than a long-lived npm token.
