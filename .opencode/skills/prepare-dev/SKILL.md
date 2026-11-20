---
name: prepare-dev
description: Prepare dev environment after release by bumping to next SNAPSHOT version and adding [NEXT] to CHANGELOG
disable-model-invocation: true
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
---

# Post-Release Dev Environment Preparation Skill

This skill documents the process to prepare the development environment after a release has been published.

## When to Use

Use this skill immediately after a release (e.g., 3.4.0) has been published to Maven Central, to prepare the codebase for the next development cycle (e.g., 3.5.0-SNAPSHOT).

## Prerequisites

- Release has been published to Maven Central
- Working directory is the project root
- Current version in POMs is the released version (e.g., 3.4.0)

## Post-Release Steps

### 1. Determine and Confirm Next Development Version

First, check the current (released) version in the project:

```bash
# Read current version from root pom.xml
CURRENT_VERSION=$(grep -m1 '<version>' pom.xml | sed -e 's/.*<version>\(.*\)<\/version>.*/\1/')
echo "Current released version: $CURRENT_VERSION"
```

The current version will be in `X.Y.Z` format (e.g., `3.4.0`).

**Suggested next development version**: Increment minor version, reset patch to 0, add `-SNAPSHOT` (e.g., `3.4.0` → `3.5.0-SNAPSHOT`).

**Confirm or override**:
- If the suggested version is correct, proceed to step 2
- If you need a different version (e.g., `3.4.1-SNAPSHOT` for patch, `4.0.0-SNAPSHOT` for major), use that version in step 2 instead

> **Note**: Typically after a release you increment the minor version for the next development cycle:
> - `3.4.0` → `3.5.0-SNAPSHOT` (standard)
> - `3.4.0` → `3.4.1-SNAPSHOT` (if only patch releases planned)
> - `3.4.0` → `4.0.0-SNAPSHOT` (if planning breaking changes)

### 2. Bump to Next SNAPSHOT Version

Run from the project root with your confirmed version:

```bash
# Replace X.Y+1.0-SNAPSHOT with your confirmed next dev version (e.g., 3.5.0-SNAPSHOT)
mvn versions:set -DnewVersion=X.Y+1.0-SNAPSHOT -DprocessAllModules=true
```

This updates:
- Root `../../../pom.xml`
- All 14 module `../../../pom.xml` files
- Inter-module dependency versions

### 3. Update Version in README.md Files

Each module has a `../../../README.md` with a dependency example. Update the version in all of them:

```bash
# List of modules with README.md files (11 files)
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

Change `<version>X.Y.Z</version>` to `<version>X.Y+1.0-SNAPSHOT</version>`

### 4. Update CHANGELOG.md

Add a new `## [NEXT]` section at the top (after the header) with empty subchapters:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [NEXT]

### Added

### Changed

### Fixed

## [3.4.0] - 2026-11-20
...
```

**Format requirements:**
- Place `## [NEXT]` immediately after the header block, before the latest release
- Include all three subchapters: `### Added`, `### Changed`, `### Fixed` (even if empty)
- Keep `### Removed` optional - only add when needed
- Maintain blank line after each subchapter header

### 5. Clean Up Backup Files

Remove Maven versions plugin backup files:

```bash
find . -name "*.versionsBackup" -delete
```

### 6. Verify Changes

```bash
# Check all POMs have the new SNAPSHOT version
grep -r "3.5.0-SNAPSHOT" --include="pom.xml" . | head -20

# Check no release version remains in POMs
grep -r "<version>3.4.0</version>" --include="pom.xml" .

# Check README.md files updated
grep -r "3.5.0-SNAPSHOT" --include="README.md" .

# Verify CHANGELOG structure
head -20 CHANGELOG.md

# Check git status
git status
```

### 7. Commit

```bash
git add -A
git commit -m "chore: prepare for next development iteration 3.5.0-SNAPSHOT"
git push origin main
```

## Version Calculation

| Current Release | Next Dev Version |
|-----------------|------------------|
| 3.4.0           | 3.5.0-SNAPSHOT   |
| 3.5.0           | 3.6.0-SNAPSHOT   |
| 2.0.0           | 2.1.0-SNAPSHOT   |

**Rule**: Increment minor version (Y), reset patch to 0, add `-SNAPSHOT`

## CHANGELOG.md Template for [NEXT]

```markdown
## [NEXT]

### Added

### Changed

### Fixed
```

**Note**: Keep subchapters even when empty - they serve as placeholders for contributors.

## Complete Example

```bash
# After releasing 3.4.0, prepare for 3.5.0-SNAPSHOT

# 1. Check current version and confirm next dev version
CURRENT_VERSION=$(grep -m1 '<version>' pom.xml | sed -e 's/.*<version>\(.*\)<\/version>.*/\1/')
echo "Current released version: $CURRENT_VERSION"
# Output: Current released version: 3.4.0

# Suggested next dev version: 3.5.0-SNAPSHOT (minor +1, patch=0, -SNAPSHOT)
# Confirm or adjust as needed

# 2. Bump version
mvn versions:set -DnewVersion=3.5.0-SNAPSHOT -DprocessAllModules=true

# 3. Update README.md files (11 files) - replace 3.4.0 with 3.5.0-SNAPSHOT

# 4. Update CHANGELOG.md - add ## [NEXT] section at top

# 5. Clean up
find . -name "*.versionsBackup" -delete

# 6. Verify
grep -r "3.4.0</version>" --include="pom.xml" --include="README.md" .
# Should return no results

grep -r "3.5.0-SNAPSHOT" --include="pom.xml" --include="README.md" . | wc -l
# Should show 26+ matches (15 POMs + 11 READMEs)

# 7. Commit
git add -A
git commit -m "chore: prepare for next development iteration 3.5.0-SNAPSHOT"
git push origin main
```

## Files Modified

- 15 `../../../pom.xml` files (root + 14 modules)
- 11 `../../../README.md` files
- 1 `../../../CHANGELOG.md` file
- Cleanup: `*.versionsBackup` files removed