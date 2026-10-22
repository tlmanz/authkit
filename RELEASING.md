# Releasing

This repository holds two Go modules, released independently:

| Module | Tag | Notes |
|---|---|---|
| `github.com/tlmanz/authkit/v2` | `v2.X.Y` | `CHANGELOG.md` |
| `github.com/tlmanz/authkit/redisstore/v2` | `redisstore/v2.X.Y` | `redisstore/CHANGELOG.md` |

Pushing a tag runs [the release workflow](.github/workflows/release.yml). It:

1. checks the tag is a semantic version whose major matches the module path
   (`/v2` only accepts `v2.x.y`);
2. runs gofmt, vet and the race-enabled tests for that module, with `GOWORK=off`
   so it is tested against what its own `go.mod` requires;
3. takes the release notes from that module's changelog section, and **fails if
   there is none**;
4. publishes the GitHub release: the written notes, followed by GitHub's list
   of merged changes since the previous tag of the same module. A tag with a
   pre-release suffix (`v2.1.0-rc.1`) is marked pre-release; a `redisstore/` tag
   never becomes "Latest";
5. asks proxy.golang.org for the new version, so a consumer's `go get` (and a
   Docker build fetching through the proxy) can use it straight away.

## Cutting a release

1. **Write the notes.** In the module's changelog, rename `## [vX.Y.Z] -
   Unreleased` to the release date (`## [v2.0.1] - 07/24/26`), or add the
   section if there is none. Say what changed for someone upgrading: fixes,
   new behaviour, anything they must do.
2. **Merge to `main`** with CI green.
3. **Tag and push** from `main`:

   ```bash
   git tag -a v2.0.1 -m "v2.0.1"
   git push origin v2.0.1
   ```

   For the Redis stores, use the prefixed tag: `redisstore/v2.0.1`.
4. **Check the run** under Actions → Release, and the release page.
5. **Update consumers**, for example:

   ```bash
   go get github.com/tlmanz/authkit/v2@v2.0.1
   go mod tidy
   ```

## When the workflow fails

The tag is already pushed, but nothing was published, so fix the cause and move
the tag:

```bash
git tag -d v2.0.1
git push origin :refs/tags/v2.0.1
# fix, merge, then tag and push again
```

Do this only before anyone has fetched the version. Once proxy.golang.org has a
version it serves that content permanently, so a published version is never
moved: release the fix as the next patch instead.
