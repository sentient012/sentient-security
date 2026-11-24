# Releasing

1. All CI checks green on `main`: typecheck, tests, pack verification, dependency audit, secret scan.
2. Update `CHANGELOG.md` and `package.json` version (SemVer; any wire-format change is a new protocol id, never a silent change).
3. Tag `vX.Y.Z` on `main`. The `release` workflow builds from the tag and publishes with
   **npm trusted publishing (OIDC) and provenance** from the protected `npm-publish` environment.
   No long-lived npm token is stored in the repository.
4. Verify: `npm view @sentient012/security@X.Y.Z dist.integrity`, `npm audit signatures` in a consumer,
   and that the provenance points at the tagged commit and workflow.
5. Consumers pin the exact version (`--save-exact`) and commit their lockfiles.

Rollback: publish a fixed patch release, or `npm deprecate` the bad version. Never `npm unpublish` a used version.

One-time setup (maintainer): create the npm org/scope, enable 2FA for publishing, and register this
repository and `.github/workflows/release.yml` as a trusted publisher for the package on npmjs.com.
