package ch.admin.bj.swiyu.jwtvalidator;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.jwtutil.JwtUtilException;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Jwk;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

/**
 * Main facade for JWT validation in the swiyu ecosystem.
 *
 * <p>Implements the <em>Flow B</em> two-step approach (no internal network calls):
 * <ol>
 *   <li>{@link #getAndValidateResolutionUrl(String)} – pre-flight check; extracts and validates
 *       the DID URL so the <strong>caller</strong> can perform the HTTP fetch.</li>
 *   <li>{@link #validateJwt(String, DidDoc)} – signature validation against the pre-fetched
 *       DID Document.</li>
 * </ol>
 * and <em>Flow A</em> for use-cases where the JWK set is already available:
 * {@link #validateJwt(String, JWKSet)}.
 *
 * <p><strong>Security rules enforced unconditionally:</strong>
 * <ul>
 *   <li>JWTs without an absolute {@code kid} header are rejected.</li>
 *   <li>The {@code iss} claim is <em>never</em> validated – trust is established
 *       exclusively via the {@code kid}.</li>
 *   <li>The resolved DID URL must match the configured Base Registry allowlist.</li>
 * </ul>
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.
 * All collaborators are injected via constructor.
 * DID operations (URL derivation, kid parsing) are delegated to {@link DidKidParser},
 * which uses the {@code didresolver} native library ({@code ch.admin.swiyu:didresolver})
 * directly – without any network calls.</p>
 */
@Slf4j
public class DidJwtValidator {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /** Default clock skew tolerance in seconds (60 s). */
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;

    private final DidKidParser didKidParser;
    private final UrlRestriction urlRestriction;
    private final int clockSkewSeconds;

    /**
     * Creates a {@code DidJwtValidator} with a default {@link DidKidParser} and
     * a clock skew of {@value #DEFAULT_CLOCK_SKEW_SECONDS} seconds.
     *
     * @param urlRestriction the Base Registry allowlist enforcer; must not be {@code null}
     */
    public DidJwtValidator(UrlRestriction urlRestriction) {
        this(new DidKidParser(), urlRestriction, DEFAULT_CLOCK_SKEW_SECONDS);
    }

    /**
     * Creates a {@code DidJwtValidator} with a default {@link DidKidParser} and configurable
     * clock skew tolerance.
     *
     * @param urlRestriction    the Base Registry allowlist enforcer; must not be {@code null}
     * @param clockSkewSeconds  acceptable clock skew in seconds (e.g. 60); must be &ge; 0
     */
    public DidJwtValidator(UrlRestriction urlRestriction, int clockSkewSeconds) {
        this(new DidKidParser(), urlRestriction, clockSkewSeconds);
    }

    /**
     * Creates a {@code DidJwtValidator} with explicit collaborators (useful for testing).
     *
     * @param didKidParser     the kid parser; must not be {@code null}
     * @param urlRestriction   the Base Registry allowlist enforcer; must not be {@code null}
     * @param clockSkewSeconds acceptable clock skew in seconds; must be &ge; 0
     */
    public DidJwtValidator(DidKidParser didKidParser, UrlRestriction urlRestriction, int clockSkewSeconds) {
        if (didKidParser == null) throw new IllegalArgumentException("didKidParser must not be null");
        if (urlRestriction == null) throw new IllegalArgumentException("urlRestriction must not be null");
        if (clockSkewSeconds < 0) throw new IllegalArgumentException("clockSkewSeconds must be >= 0");
        this.didKidParser = didKidParser;
        this.urlRestriction = urlRestriction;
        this.clockSkewSeconds = clockSkewSeconds;
    }

    /**
     * Extracts and returns the DID string from the JWT's {@code kid} header.
     *
     * <p>Use this method to obtain the DID string needed for calling
     * {@code resolveDid(didString, didLog)} after fetching the DID log via
     * {@link #getAndValidateResolutionUrl(String)}, avoiding a redundant manual extraction
     * from the {@code kid}.</p>
     *
     * @param jwtString the compact serialized JWT
     * @return the DID string (e.g. {@code did:tdw:Qm...:identifier.admin.ch})
     * @throws JwtValidatorException if the JWT is malformed or the {@code kid} is missing /
     *                               not absolute
     */
    public String getDidString(String jwtString) {
        String kid = didKidParser.extractKidFromHeader(jwtString);
        return didKidParser.getDidFromAbsoluteKid(kid);
    }

    /**
     * Step 1 of Flow B – extracts the DID resolution URL from the JWT and validates it
     * against the Base Registry allowlist.
     *
     * <p>The caller is expected to perform the HTTP GET to the returned URL to fetch the
     * DID Document, and then call {@link #validateJwt(String, DidDoc)} with the result.</p>
     *
     * @param jwtString the compact serialized JWT
     * @return the validated DID resolution URL (HTTPS) for the caller to fetch
     * @throws JwtValidatorException if the JWT is malformed, the {@code kid} is missing or
     *                               not absolute, the DID cannot be resolved to a URL, or the
     *                               URL is not on the Base Registry allowlist
     */
    public String getAndValidateResolutionUrl(String jwtString) {
        String kid = didKidParser.extractKidFromHeader(jwtString);
        String didString = didKidParser.getDidFromAbsoluteKid(kid);

        String didUrl = resolveDidToUrl(didString);
        log.debug("Resolved DID '{}' to URL '{}'", didString, didUrl);

        if (!urlRestriction.validateUrl(didUrl)) {
            throw new JwtValidatorException(
                    "DID URL '" + didUrl + "' is not permitted by the Base Registry allowlist");
        }
        return didUrl;
    }

    /**
     * Step 2 of Flow B – validates the JWT signature against the pre-fetched DID Document.
     *
     * <p>The public key is extracted from {@code didDocument} using the {@code kid} from the
     * JWT header via {@code getKeyByMethodId(kid)}.
     * The {@code iss} claim is <em>not</em> validated; trust is established solely via the
     * {@code kid}.</p> which is extracted from the JWT header and used to find the corresponding public key in the DID Document.
     *
     * @param jwtString   the compact serialized JWT
     * @param didDocument the resolved DID Document containing the verification methods
     * @throws JwtValidatorException if the JWT is malformed, the key cannot be found in the
     *                               DID Document, or the signature verification fails
     */
    public void validateJwt(String jwtString, DidDoc didDocument) {
        String kid = didKidParser.extractKidFromHeader(jwtString);

        validateJwt(jwtString, didDocument, kid);
    }


    /**
     * Step 2 of Flow B – validates the JWT signature against the pre-fetched DID Document.
     *
     * <p>This method uses the provided {@code kid} to extract the corresponding public key
     * from the {@code didDocument} and then performs the standard validation steps:
     *
     * @param jwtString   the compact serialized JWT
     * @param didDocument the resolved DID Document containing the verification methods
     * @param kid         the absolute verification method id (kid) to use for signature verification
     * @throws JwtValidatorException if the JWT is malformed, the key cannot be found in the
      *                               DID Document, or the signature verification fails
     */
    public void validateJwt(String jwtString, DidDoc didDocument, String kid) {

        Jwk jwk;
        try {
            jwk = didDocument.getKeyByMethodId(kid);
        } catch (DidSidekicksException e) {
            throw new JwtValidatorException("Key '" + kid + "' not found in DID Document", e);
        }

        validateTimeClaims(jwtString);
        JWKSet jwkSet = toJwkSet(jwk);
        verifySignature(jwtString, jwkSet);
    }

    /**
     * Flow A – validates the JWT signature directly against the provided JWK set.
     *
     * <p>Use this method when the JWK set is already available (e.g. for Trust Statements)
     * and no DID resolution is required.
     * The {@code iss} claim is <em>not</em> validated; trust is established solely via the
     * {@code kid}.</p>
     *
     * @param jwtString the compact serialized JWT
     * @param jwkSet    the JWK set containing the public key(s) to verify against
     * @throws JwtValidatorException if the JWT is malformed, no matching key is found in the
     *                               JWK set, or the signature verification fails
     */
    public void validateJwt(String jwtString, JWKSet jwkSet) {
        // Validate kid header presence before delegating to JwtUtil
        didKidParser.extractKidFromHeader(jwtString);
        validateTimeClaims(jwtString);
        verifySignature(jwtString, jwkSet);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Validates the time-based JWT claims ({@code exp} and {@code nbf}) using Nimbus
     * {@link DefaultJWTClaimsVerifier} with the configured clock skew tolerance.
     *
     * <p>The {@code iss} claim is intentionally <em>ignored</em> (not verified, not forbidden)
     * per PARENT-ADR-027. {@code exp} and {@code nbf} are checked when present.</p>
     *
     * @param jwtString the compact serialized JWT
     * @throws JwtValidatorException if {@code exp} or {@code nbf} are violated
     */
    private void validateTimeClaims(String jwtString) {
        try {
            SignedJWT jwt = SignedJWT.parse(jwtString);
            DefaultJWTClaimsVerifier<SecurityContext> verifier = new DefaultJWTClaimsVerifier<>(
                    null,                  // no required audience
                    new JWTClaimsSet.Builder().build(), // no exact match required
                    Set.of(),              // no required claims (exp/nbf checked if present)
                    Set.of()               // no prohibited claims – iss is ignored, not forbidden
            );
            verifier.setMaxClockSkew(clockSkewSeconds);
            verifier.verify(jwt.getJWTClaimsSet(), null);
            log.debug("JWT time claims (exp/nbf) verified successfully");
        } catch (ParseException e) {
            throw new JwtValidatorException("Failed to parse JWT for claims verification", e);
        } catch (BadJOSEException e) {
            throw new JwtValidatorException("JWT time claim validation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Resolves a DID string to its HTTPS URL using the didresolver library.
     *
     * @param didString the DID string
     * @return the HTTPS URL for fetching the DID log
     * @throws JwtValidatorException if the DID string is invalid or URL resolution fails
     */
    private String resolveDidToUrl(String didString) {
        try (Did did = new Did(didString)) {
            return did.getUrl();
        } catch (DidResolveException e) {
            throw new JwtValidatorException("Cannot resolve DID '" + didString + "' to URL", e);
        }
    }

    /**
     * Converts the did_sidekicks {@link Jwk} data class to a Nimbus {@link JWKSet}.
     *
     * @param jwk the JWK from the DID Document
     * @return a single-key {@link JWKSet}
     * @throws JwtValidatorException if the JWK cannot be parsed
     */
    private JWKSet toJwkSet(Jwk jwk) {
        try {
            return new JWKSet(JWK.parse(buildJwkMap(jwk)));
        } catch (ParseException | IllegalArgumentException e) {
            throw new JwtValidatorException("Failed to convert JWK from DID Document", e);
        }
    }

    /**
     * Converts the Jwk data class into a generic Map representation for Nimbus.
     * Automatically handles any key type (EC, OKP, RSA) dynamically.
     *
     * @param jwk the source JWK
     * @return map of JWK fields
     */
    private Map<String, Object> buildJwkMap(Jwk jwk) {
        return OBJECT_MAPPER.convertValue(jwk, new TypeReference<>() {
        });
    }

    /**
     * Delegates signature verification to {@link JwtUtil} and maps any exception to
     * {@link JwtValidatorException}.
     *
     * @param jwtString the compact serialized JWT
     * @param jwkSet    the JWK set to verify against
     * @throws JwtValidatorException if verification fails for any reason
     */
    private void verifySignature(String jwtString, JWKSet jwkSet) {
        try {
            JwtUtil.verifyJwt(jwtString, jwkSet);
            log.debug("JWT signature verification succeeded");
        } catch (JwtUtilException e) {
            throw new JwtValidatorException("JWT signature verification failed", e);
        }
    }
}
