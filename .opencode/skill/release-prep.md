# Release Preparation Skill

This skill documents the release preparation process for the swiyu-generic-java-lib project.

## When to Use

Use this skill when preparing a new release of the swiyu-generic-java-lib library set.

## Prerequisites

- JDK 25 + Maven
- All tests passing (`mvn clean verify`)
- Working directory is the project root

## Release Preparation Steps

### 1. Determine and Confirm Release Version

First, check the current version in the project:

```bash
# Read current version from root pom.xml
CURRENT_VERSION=$(grep -m1 '<version>' pom.xml | sed -e 's/.*<version>\(.*\)<\/version>.*/\1/')
echo "Current version: $CURRENT_VERSION"
```

The current version will be in `X.Y.Z-SNAPSHOT` format (e.g., `3.4.0-SNAPSHOT`).

**Suggested release version**: Remove `-SNAPSHOT` suffix (e.g., `3.4.0`).

**Confirm or override**:
- If the suggested version is correct, proceed to step 2
- If you need a different version (e.g., `3.4.1`, `3.5.0`, `4.0.0`), use that version in step 2 instead

> **Note**: The release version should follow [Semantic Versioning](https://semver.org/). Typically:
> - Patch increment (3.4.0 → 3.4.1): bug fixes only
> - Minor increment (3.4.0 → 3.5.0): new features, backward compatible
> - Major increment (3.4.0 → 4.0.0): breaking changes

### 2. Update Version in All POMs

Run from the project root with your confirmed version:

```bash
# Replace X.Y.Z with your confirmed release version (e.g., 3.4.0)
mvn versions:set -DnewVersion=X.Y.Z -DprocessAllModules=true
```

This updates:
- Root `pom.xml`
- All 14 module `pom.xml` files
- Inter-module dependency versions

### 2. Update Version in README.md Files

Each module has a `README.md` with a dependency example. Update the version in all of them:

```bash
# List of modules with README.md files
swiyu-jwt-util/README.md
swiyu-ts-builder/README.md
swiyu-did-resolver-adapter/README.md
swiyu-sdjwt-builder/README.md
swiyu-sdjwt-verifier/README.md
swiyu-sdjwt-util/README.md
swiyu-jws-signature-service/README.md
swiyu-dpop-util/README.md
swiyu-jwe-util/README.md
swiyu-jwt-validator/README.md
swiyu-token-status-list/README.md
```

Change `<version>X.Y.Z-SNAPSHOT</version>` to `<version>X.Y.Z</version>`

### 3. Update CHANGELOG.md

Replace the `## [NEXT]` header with the release version and current date:

```markdown
## [X.Y.Z] - YYYY-MM-DD
```

**Preserve the original issue reference format:**
- Keep parentheses: `(#1234)`
- Keep ticket prefixes: `(#EIDOMNI-1234)`
- Match the format used in previous releases

### 4. Clean Up Backup Files

Remove Maven versions plugin backup files:

```bash
find . -name "*.versionsBackup" -delete
```

### 5. Verify Changes

```bash
# Check no SNAPSHOT references remain in actual files
grep -r "SNAPSHOT" --include="pom.xml" --include="README.md" .

# Verify CHANGELOG format
head -30 CHANGELOG.md

# Check git status
git status
```

### 6. Commit and Tag

```bash
git add -A
git commit -m "chore(release): prepare release X.Y.Z"
git tag -a "X.Y.Z" -m "Release X.Y.Z"
git push origin main --tags
```

## Version Bumping Notes

- **No parent POM**: Each of the 14 module POMs repeats its own version
- Version bumps must touch all 15 POMs (root + 14 modules)
- The release workflow (`.github/workflows/maven-central-publish.yml`) publishes to Maven Central when a GitHub release is created
- Do NOT run `mvn deploy` locally - `central-publishing-maven-plugin` handles publishing

## Changelog Format Reference

Follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) with these conventions:

- Sections: `### Changed`, `### Fixed`, `### Added`, `### Removed`
- Issue references: `(#1234)` or `(#EIDOMNI-1234)` in parentheses
- One entry per line, prefixed with `- `
- Module prefix: `` `swiyu-module-name`: ``

## Example

```bash
# 1. Check current version
CURRENT_VERSION=$(grep -m1 '<version>' pom.xml | sed -e 's/.*<version>\(.*\)<\/version>.*/\1/')
echo "Current version: $CURRENT_VERSION"
# Output: Current version: 3.4.0-SNAPSHOT

# 2. Confirm release version (remove -SNAPSHOT)
# Suggested: 3.4.0
# If different version needed, adjust below

# 3. Bump to release version
mvn versions:set -DnewVersion=3.4.0 -DprocessAllModules=true

# 4. Update README.md files (11 files)
# Update CHANGELOG.md (replace ## [NEXT] with ## [3.4.0] - 2026-11-20)

# 5. Clean up
find . -name "*.versionsBackup" -delete

# 6. Verify
grep -r "3.4.0-SNAPSHOT" --include="pom.xml" --include="README.md" .
# Should return no results
```