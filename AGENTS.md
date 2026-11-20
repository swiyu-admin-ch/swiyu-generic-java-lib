# AGENTS.md

Multi-module Maven library set for the Swiss **swiyu** (eID) ecosystem: JWT/DID validation, SD-JWT VCs, JWE, DPoP, token status lists, and Trust Statements. The artifacts are libraries, not applications; some expose Spring Boot auto-configuration. Published to Maven Central as `ch.admin.swiyu:*`; Java packages use `ch.admin.bj.swiyu.<module>` (note `bj`, not `swiyu`).

## Build and test

- Toolchain: **JDK 25** + Maven. Every POM sets `<release>25</release>`; the root README still says Java 21 and is stale.
- `mvn clean install` — full build with tests, sources and javadoc jars (~1.5 min). Javadoc errors can fail the build.
- `mvn test` — run all tests.
- Single module: `mvn -pl swiyu-jwt-validator -am test`. Modules have **no Maven parent** and consume sibling artifacts via `${project.version}`, so `-am` (or a prior `mvn install`) is required whenever that version is not already published.
- Single test: `mvn -pl swiyu-jwt-validator -am test -Dtest=DidJwtValidatorTest -Dsurefire.failIfNoSpecifiedTests=false`.
- No formatter or linter is wired into Maven. PMD (`.github/rulesets/java/pmd_omni_ruleset.xml`), CodeQL, and a high-severity Snyk gate run only in the PR workflow (`.github/workflows/pull-request-check.yml`), which runs `mvn clean verify`. Use that as the pre-push check.
- Tests are plain JUnit 5 + AssertJ + Mockito: no Spring context, no test resources, no external services. HSM/PKCS#11 code is mocked.

## Module map (dependency-relevant facts)

- `swiyu-jwt-validator` — security core (`DidJwtValidator`): rejects relative `kid`, never validates `iss`, enforces a Base Registry URL allowlist, performs no network I/O (callers fetch DID docs). Uses the native `ch.admin.swiyu:didresolver` via JNA; native-access warnings and expected native-call failures in unit tests are normal.
- `swiyu-sdjwt-builder` / `swiyu-sdjwt-verifier` — SD-JWT VC issuance/validation; constants in `swiyu-sdjwt-util`. The verifier delegates signature checks to `swiyu-jwt-validator` and uses `com.authlete:sd-jwt`.
- `swiyu-ts-builder` / `swiyu-ts-verifier` — Trust Statement builders and the `TrustStatementVerifier` facade; the verifier depends on `swiyu-jwt-validator` and `swiyu-token-status-list`.
- `swiyu-jws-signature-service` — creates Nimbus signers through strategies named `key` (software), `pkcs11`, `securosys`. Spring auto-config lives in `META-INF/spring/...AutoConfiguration.imports`, as it does for `swiyu-did-resolver-adapter`.
- `swiyu-jwe-util` — JWE AES-256-GCM encryption and decompression-bomb-limited decryption; do not reintroduce the deprecated limit-less `decrypt` overloads.
- `swiyu-generic-java-all` — dependency aggregator only. It currently **omits** `swiyu-token-status-list` and `swiyu-ts-verifier`; add them explicitly if needed. Its `dependencyManagement` pins `tomcat-embed-core` and `logback-classic` for CVE fixes — do not drop those pins casually.

## Gotchas

- **Jackson 3, not Jackson 2**: databind/core imports are `tools.jackson.databind.*` / `tools.jackson.core.*`, while annotations remain `com.fasterxml.jackson.annotation.*`. Do not "fix" these to `com.fasterxml.jackson.databind`.
- **No parent POM**: each of the 14 module POMs repeats its own version, metadata, compiler/Lombok, javadoc, source, and publishing plugins. Adding a module means a new POM (copy an existing one), an entry in the root `<modules>`, and optionally a dependency in `swiyu-generic-java-all`.
- Version bumps must touch all 15 POMs; use `mvn versions:set -DnewVersion=X` from the root, as the release workflow does.
- **Releases are GitHub-release driven**: publishing a release runs `.github/workflows/maven-central-publish.yml`, which sets the version from the tag and deploys with `-Psign-artifacts`. Do not run `mvn deploy` locally — `maven-deploy-plugin` is skipped and `central-publishing-maven-plugin` handles publishing.
- The changelog/release conversation flow is in `.github/instructions/make-release.instructions.md` (German; triggered by "Starte Release"). `CHANGELOG.md` follows Keep a Changelog; put unreleased items under `[NEXT]`.
- Lombok is `provided` and must be registered as an `annotationProcessorPath` in a module's compiler plugin configuration (already done wherever Lombok is used).
- Conventions: branches `feature/EIDOMNI-<n>-...`, `fix/EIDSEC-<n>-...`, `release/<x.y.z or x.y.x>`; commits use `type(SCOPE): summary` with a ticket reference.
