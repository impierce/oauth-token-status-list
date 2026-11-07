# Release process

Releases are automated with [release-plz](https://release-plz.dev/) and follow
[Cargo's SemVer rules](https://doc.rust-lang.org/cargo/reference/semver.html). Versions and
`CHANGELOG.md` are written by release-plz in the release pull request; the only place to edit either
by hand is that pull request, shortly before it merges (step 2 below), never `main` directly.

## Flow

1. On every push to `main`, release-plz opens or updates a release pull request
   (`chore: release vX.Y.Z`, labelled `release`). It contains the next version in `Cargo.toml` and
   a new `CHANGELOG.md` entry, both derived from the
   [Conventional Commits](https://www.conventionalcommits.org/) on `main` since the last release.
   Once a version is on crates.io, release-plz runs
   [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) against it, so an
   API-breaking change can't go out as a compatible version.
2. A maintainer reviews the version and changelog. To adjust them, commit to the release branch
   shortly before merging, since release-plz regenerates the pull request whenever `main` changes.
3. Approving and merging the release pull request publishes the crate to
   [crates.io](https://crates.io/crates/token-status-list), then tags the commit as `vX.Y.Z` and
   creates a GitHub release with the same changelog. Nothing is published before that merge.
4. The workflow then attaches the published `.crate` to the GitHub release, as crates.io serves it,
   together with its signed [SLSA](https://slsa.dev/) build provenance
   (`token-status-list-X.Y.Z.crate.intoto.jsonl`); see [Verifying a release](#verifying-a-release).

## First release

crates.io accepts a [trusted publisher](https://crates.io/docs/trusted-publishing) only for a crate
that already exists, so the first version is published by hand:

1. Check out the first release pull request's branch and run `cargo publish` with a maintainer's
   crates.io API token.
2. On crates.io, add `impierce/token-status-list`, workflow `release-plz.yml`, environment
   `release` as trusted publisher of `token-status-list`, and revoke the token if it was made for
   this.
3. Merge the release pull request. release-plz finds the version already published and does not
   publish it again. If it did not tag the merge commit either, create the tag and GitHub release by
   hand: `gh release create vX.Y.Z --target main --title vX.Y.Z --notes-file <the changelog entry>`.

The first version has no provenance, since the workflow did not publish it. Every later release
follows [Flow](#flow).

## Verifying a release

Each release after the first carries SLSA build level 3 provenance, made by
[`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator) and signed through
Sigstore. It states that the `.crate` was published by `release-plz.yml` in this repository, run by
the push to `main` that merged the release pull request; the commit it names is the one `vX.Y.Z`
points to. To check a crate, download both files from the GitHub release and run
[`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier):

```sh
slsa-verifier verify-artifact token-status-list-X.Y.Z.crate \
  --provenance-path token-status-list-X.Y.Z.crate.intoto.jsonl \
  --source-uri github.com/impierce/token-status-list \
  --source-branch main
```

If attaching them fails after the crate is published (crates.io slow to index it, a GitHub
outage), run the Release-plz workflow by hand from the release's tag (Actions → Release-plz → Run
workflow → Use workflow from → Tags → `vX.Y.Z`). It attaches the crate and provenance to that
release without publishing anything, and refuses to run from a branch. Its provenance names the
tag and the commit it points to, so verify such a release with `--source-tag vX.Y.Z` in place of
`--source-branch main`.

The attached `.crate` is the file crates.io serves: the workflow checks it against the checksum in
the crates.io index before attaching it. That checksum is also the `checksum` of `token-status-list`
in a dependent's `Cargo.lock`, so `sha256sum token-status-list-X.Y.Z.crate` ties the provenance to
the crate a build actually used.

## Versioning

Before 1.0, a breaking change (`feat!:`, `fix!:` or one detected by `cargo-semver-checks`) bumps the
minor version (`0.1.3` → `0.2.0`), and anything else bumps the patch version (`0.1.3` → `0.1.4`).

Pull requests are squash-merged, so the pull request title is the commit that release-plz reads. The
`PR title` check requires a [Conventional Commits](https://www.conventionalcommits.org/) title,
`type(scope): description` with `!` before the colon for a breaking change, for example
`feat(status_list): support aggregation_uri` or `fix!: reject index beyond list length`.

## Changelog

Only commits that matter to users of the crate appear in the changelog: `ci`, `test`, `style` and
`chore` commits are left out, except dependency updates (`chore(deps)`). The rules are configured in
[`release-plz.toml`](../release-plz.toml).

## Credentials

The [release workflow](../.github/workflows/release-plz.yml) runs without long-lived publishing
credentials:

- crates.io accepts the upload through
  [trusted publishing](https://crates.io/docs/trusted-publishing), only from `release-plz.yml`
  running in the `release` environment, which is limited to `main`.
- The release pull request, tags and GitHub releases are created by the `impierce-release-plz`
  GitHub App, so CI runs on the release pull request like on any other. The App's credentials are
  stored in the repository variable `RELEASE_PLZ_CLIENT_ID` and the secret
  `RELEASE_PLZ_PRIVATE_KEY`.
