package ch.admin.bj.swiyu.tsbuilder;

import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import ch.admin.bj.swiyu.jwssignatureservice.factory.KeyManagementStrategyFactory;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategy;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration Test for Trust Management Statements (TMS).
 *
 * <p><b>What is tested and why:</b><br>
 * Verifies the full happy-path pipeline of building a Trust Statement JWT with each concrete
 * builder, signing it via the {@link JwsSignatureService} using a software EC key (ES256),
 * and confirming the resulting compact JWS is cryptographically valid. This test ensures
 * that the builder output ({@link TrustStatementJwt#getJwsHeader()}/{@link TrustStatementJwt#getClaimsSet()}) and the signing
 * service are correctly wired together end-to-end.
 *
 * <p><b>Boundary conditions:</b><br>
 * A fresh, ephemeral P-256 EC key pair is generated in memory once per test run.
 * No private key material is stored in source control, on disk, or in any configuration file.
 * No external services, databases, or Spring application context are required.
 * All trust statements use a validity window of iat = now, exp = now + 365 days.
 *
 * <p><b>Expected result:</b><br>
 * For every builder, the signed compact JWS:
 * <ul>
 *   <li>verifies successfully against the corresponding EC public key</li>
 *   <li>carries the correct {@code typ} header defined by Trust Protocol 2.0</li>
 *   <li>carries {@code alg = ES256}</li>
 * </ul>
 */
class TMS_IT {

    private static final String KID = "did:tdw:example.ch:trust-issuer#assert-key-01";
    private static final String SUBJECT_DID = "did:example:actor";
    private static final String VERIFIER_DID = "did:example:verifier";
    private static final String ISSUER_DID = "did:example:issuer";

    private static JwsSignatureService jwsSignatureService;
    private static SignatureConfigurationDto signatureConfig;
    private static ECKey ecPublicKey;

    /**
     * Generates a fresh, ephemeral P-256 EC key pair for this test run.
     * The private key exists only in JVM memory and is never written to disk or source control.
     * Wires up {@link JwsSignatureService} with the {@code key} strategy (BouncyCastle, ES256)
     * without a Spring application context.
     */
    @BeforeAll
    static void setUpSigningInfrastructure() throws Exception {
        // Generate ephemeral P-256 key pair via JCA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        java.security.KeyPair keyPair = kpg.generateKeyPair();

        // Build Nimbus ECKey for public key extraction (verification side)
        ecPublicKey = ECKey.parse(buildPublicKeyJson(
                (ECPublicKey) keyPair.getPublic()));

        // Build PEM with PKCS#8 private key block + X.509 public key block
        // KeyStrategy calls JWK.parseFromPEMEncodedObjects which accepts this combination
        String pemForSigning = toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded())
                + toPem("PUBLIC KEY", keyPair.getPublic().getEncoded());

        jwsSignatureService = new JwsSignatureService(
                new KeyManagementStrategyFactory(Map.of("key", new KeyStrategy())),
                new ObjectMapper()
        );

        signatureConfig = SignatureConfigurationDto.builder()
                .keyManagementMethod("key")
                .privateKey(pemForSigning)
                .verificationMethod(KID)
                .build();
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    @Test
    void givenValidIdTs_whenSignedWithEcKey_thenJwtVerifiesSuccessfully() throws Exception {
        TrustStatementJwt ts = new IdTsBuilder()
                .withKid(KID)
                .withSubject(SUBJECT_DID)
                .withValidity(now(), expiresAt())
                .withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("John Smith's Smithery")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000")
                .build();

        SignedJWT signed = signAndParse(ts);

        assertTrue(signed.verify(verifier()), "idTS signature must be valid");
        assertEquals("swiyu-identity-trust-statement+jwt", signed.getHeader().getType().getType());
        assertEquals(JWSAlgorithm.ES256, signed.getHeader().getAlgorithm());
    }

    @Test
    void givenValidVqPs_whenSignedWithEcKey_thenJwtVerifiesSuccessfully() throws Exception {
        TrustStatementJwt ts = new VqPsBuilder()
                .withKid(KID)
                .withJti(randomUuidV4())
                .withSubject(VERIFIER_DID)
                .withValidity(now(), expiresAt())
                .addPurposeName("Identity verification")
                .addPurposeDesc("Verify the identity of the user for access control.")
                .withRequest("com.example.identityCardCredential_presentation", buildDcqlQuery())
                .build();

        SignedJWT signed = signAndParse(ts);

        assertTrue(signed.verify(verifier()), "vqPS signature must be valid");
        assertEquals("swiyu-verification-query-public-statement+jwt",
                signed.getHeader().getType().getType());
        assertEquals(JWSAlgorithm.ES256, signed.getHeader().getAlgorithm());
    }

    @Test
    void givenValidPvaTs_whenSignedWithEcKey_thenJwtVerifiesSuccessfully() throws Exception {
        TrustStatementJwt ts = new PvaTsBuilder()
                .withKid(KID)
                .withJti(randomUuidV4())
                .withSubject(VERIFIER_DID)
                .withValidity(now(), expiresAt())
                .withStatus(0, "https://example.com/statuslists/1")
                .withAuthorizedFields(List.of("personal_administrative_number"))
                .build();

        SignedJWT signed = signAndParse(ts);

        assertTrue(signed.verify(verifier()), "pvaTS signature must be valid");
        assertEquals("swiyu-protected-verification-authorization-trust-statement+jwt",
                signed.getHeader().getType().getType());
        assertEquals(JWSAlgorithm.ES256, signed.getHeader().getAlgorithm());
    }

    @Test
    void givenValidPiaTs_whenSignedWithEcKey_thenJwtVerifiesSuccessfully() throws Exception {
        TrustStatementJwt ts = new PiaTsBuilder()
                .withKid(KID)
                .withSubject(ISSUER_DID)
                .withValidity(now(), now().plusSeconds(3600), expiresAt())
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue("urn:ch.admin.fedpol.betaid", null, "Beta credential", null)
                .build();

        SignedJWT signed = signAndParse(ts);

        assertTrue(signed.verify(verifier()), "piaTS signature must be valid");
        assertEquals("swiyu-protected-issuance-authorization-trust-statement+jwt",
                signed.getHeader().getType().getType());
        assertEquals(JWSAlgorithm.ES256, signed.getHeader().getAlgorithm());
    }

    @Test
    void givenValidPiTls_whenSignedWithEcKey_thenJwtVerifiesSuccessfully() throws Exception {
        TrustStatementJwt ts = new PiTlsBuilder()
                .withKid(KID)
                .withJti(randomUuidV4())
                .withValidity(now(), now().plusSeconds(3600), expiresAt())
                .withStatus(0, "https://example.com/statuslists/1")
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"))
                .build();

        SignedJWT signed = signAndParse(ts);

        assertTrue(signed.verify(verifier()), "piTLS signature must be valid");
        assertEquals("swiyu-protected-issuance-trust-list-statement+jwt",
                signed.getHeader().getType().getType());
        assertEquals(JWSAlgorithm.ES256, signed.getHeader().getAlgorithm());
    }

    @Test
    void givenValidNcTls_whenSignedWithEcKey_thenJwtVerifiesSuccessfully() throws Exception {
        TrustStatementJwt ts = new NcTlsBuilder()
                .withKid(KID)
                .withValidity(now(), expiresAt())
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(
                        new NcTlsBuilder.NonCompliantActorBuilder(
                                "did:example:badActor",
                                "2026-02-25T07:07:35Z",
                                "Actor is not who they claim to be"
                        )
                )
                .build();

        SignedJWT signed = signAndParse(ts);

        assertTrue(signed.verify(verifier()), "ncTLS signature must be valid");
        assertEquals("swiyu-non-compliance-trust-list-statement+jwt",
                signed.getHeader().getType().getType());
        assertEquals(JWSAlgorithm.ES256, signed.getHeader().getAlgorithm());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Signs the given {@link TrustStatementJwt} via the {@link JwsSignatureService} and
     * returns a {@link SignedJWT} ready for verification.
     * <p>
     * Mirrors the pattern used in production: builds a {@link JWSHeader} from the trust
     * statement header claims, parses the payload into a {@link JWTClaimsSet}, constructs
     * a {@link SignedJWT} and signs it with the configured key.
     *
     * @param ts the assembled, unsigned trust statement
     * @return the signed {@link SignedJWT}
     */
    private SignedJWT signAndParse(TrustStatementJwt ts) throws Exception {
        SignedJWT jwt = new SignedJWT(ts.getJwsHeader(), ts.getClaimsSet());
        jwt.sign(jwsSignatureService.createSigner(signatureConfig));
        return jwt;
    }

    /** Returns a {@link JWSVerifier} backed by the ephemeral EC public key. */
    private JWSVerifier verifier() throws Exception {
        return new ECDSAVerifier(ecPublicKey);
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS);
    }

    private static Instant expiresAt() {
        return now().plus(365, ChronoUnit.DAYS);
    }

    /** Returns a random UUIDv4 string. */
    private static String randomUuidV4() {
        return UUID.randomUUID().toString();
    }

    /**
     * Encodes a DER byte array as a PEM block with the given label.
     *
     * @param label   PEM label, e.g. {@code "PRIVATE KEY"} or {@code "PUBLIC KEY"}
     * @param encoded DER-encoded key bytes
     * @return PEM string including header, base64 body and footer
     */
    private static String toPem(String label, byte[] encoded) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    }

    /**
     * Builds a minimal JWK JSON string for an EC public key on P-256 so that
     * Nimbus can parse it back to an {@link ECKey} for use in the {@link ECDSAVerifier}.
     *
     * @param pub the EC public key
     * @return JWK JSON string
     */
    private static String buildPublicKeyJson(ECPublicKey pub) {
        // Extract raw x/y coordinates from the uncompressed EC point (04 || x || y)
        byte[] x = toUnsigned32(pub.getW().getAffineX().toByteArray());
        byte[] y = toUnsigned32(pub.getW().getAffineY().toByteArray());
        String xB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(x);
        String yB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(y);
        return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + xB64 + "\",\"y\":\"" + yB64 + "\"}";
    }

    /**
     * Normalises a BigInteger byte array to exactly 32 bytes (P-256 field size),
     * removing any leading zero sign byte or padding with leading zeros as needed.
     *
     * @param bytes the raw BigInteger byte array
     * @return a 32-byte unsigned big-endian representation
     */
    private static byte[] toUnsigned32(byte[] bytes) {
        byte[] result = new byte[32];
        if (bytes.length == 33 && bytes[0] == 0) {
            // strip leading sign byte
            System.arraycopy(bytes, 1, result, 0, 32);
        } else if (bytes.length <= 32) {
            System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
        }
        return result;
    }

    /**
     * Builds a minimal but spec-compliant DCQL query for a vqPS request.
     *
     * @return a {@link Map} representing the DCQL query object
     */
    private static Map<String, Object> buildDcqlQuery() {
        return Map.of(
                "credentials", List.of(
                        Map.of(
                                "id", "my_credential",
                                "format", "dc+sd-jwt",
                                "meta", Map.of(
                                        "vct_values", List.of(
                                                "https://credentials.example.com/identity_credential"
                                        )
                                ),
                                "claims", List.of(
                                        Map.of("path", List.of("last_name")),
                                        Map.of("path", List.of("first_name"))
                                )
                        )
                )
        );
    }
}
