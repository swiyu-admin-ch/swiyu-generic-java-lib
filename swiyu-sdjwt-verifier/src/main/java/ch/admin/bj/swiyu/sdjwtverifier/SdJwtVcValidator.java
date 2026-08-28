package ch.admin.bj.swiyu.sdjwtverifier;

import java.util.Map;

import com.nimbusds.jose.jwk.JWK;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Validates SD-JWT VC tokens according to the Swiss Profile VC specification (RFC 9901).
 *
 * <p>Acts as an <strong>orchestrator</strong> that delegates each validation concern to a
 * dedicated collaborator, extending the base DID-based JWT validation provided by
 * {@link DidJwtValidator} with SD-JWT VC specific rules mandated by the Swiss Profile:</p>
 * <ul>
 *   <li>{@link SdJwtHeaderValidator}: {@code typ}/{@code kid} JOSE header requirements</li>
 *   <li>{@link SdJwtSignatureValidator}: DID-anchored signature validation</li>
 *   <li>{@link SdJwtKeyBindingValidator}: Key Binding JWT verification (RFC 9901 §7.3)</li>
 *   <li>{@link SdJwtTimeClaimsValidator}: {@code exp}/{@code nbf} claim validation</li>
 *   <li>{@link SdJwtDisclosureProcessor}: resolving selectively disclosed claims (RFC 9901 §7.1),
 *       including the {@code _sd_alg} = {@code sha-256} requirement and the rule that registered
 *       claims ({@code iss}, {@code nbf}, {@code exp}, {@code iat}, {@code cnf}, {@code vct},
 *       {@code vct#integrity}, {@code status}, {@code vct_metadata_uri},
 *       {@code vct_metadata_uri#integrity}, {@code _sd}, {@code _sd_alg}) MUST NOT appear as
 *       selectively disclosed claims (RFC 9901 §3.2.2.2)</li>
 * </ul>
 *
 * <p><strong>Typical usage:</strong></p>
 * <pre>{@code
 * SdJwtVcValidator validator = new SdJwtVcValidator(didJwtValidator);
 * SdJwt sdJwt = SdJwtParser.parseSdJwt(serializedSdJwt);
 *
 * validator.validateHeader(sdJwt);
 * // issuerJwk is resolved by the caller, e.g. via the DID Document for sdJwt.getHeader().getKeyID()
 * validator.validateJwt(sdJwt, issuerJwk);
 *
 * if (sdJwt.hasKeyBinding()) {
 *     validator.validateKeyBinding(sdJwt, audience, nonce, acceptableProofTimeWindowSeconds);
 * }
 *
 * Map<String, Object> claims = validator.processDisclosures(sdJwt);
 * }</pre>
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
public class SdJwtVcValidator {

    private final SdJwtHeaderValidator headerValidator;
    private final SdJwtSignatureValidator signatureValidator;
    private final SdJwtKeyBindingValidator keyBindingValidator;
    private final SdJwtTimeClaimsValidator timeClaimsValidator;
    private final SdJwtDisclosureProcessor disclosureProcessor;

    /**
     * Creates an {@code SdJwtVcValidator} that accepts only {@code dc+sd-jwt} as {@code typ}.
     *
     * @param didJwtValidator the underlying DID-based JWT validator; must not be {@code null}
     */
    public SdJwtVcValidator(DidJwtValidator didJwtValidator) {
        this(new SdJwtHeaderValidator(),
                new SdJwtSignatureValidator(didJwtValidator),
                new SdJwtKeyBindingValidator(),
                new SdJwtTimeClaimsValidator(),
                new SdJwtDisclosureProcessor());
    }

    /**
     * Package-private constructor allowing collaborators to be injected, e.g. for unit testing
     * the orchestration logic in isolation from the individual validators.
     */
    SdJwtVcValidator(SdJwtHeaderValidator headerValidator,
                      SdJwtSignatureValidator signatureValidator,
                      SdJwtKeyBindingValidator keyBindingValidator,
                      SdJwtTimeClaimsValidator timeClaimsValidator,
                      SdJwtDisclosureProcessor disclosureProcessor) {
        this.headerValidator = headerValidator;
        this.signatureValidator = signatureValidator;
        this.keyBindingValidator = keyBindingValidator;
        this.timeClaimsValidator = timeClaimsValidator;
        this.disclosureProcessor = disclosureProcessor;
    }

    /**
     * Validates the header to conform to swiss-profile 1.0 requirements.
     * Makes the header available in the provided {@link SdJwt} object
     * @param sdJwt The sdJwt which will be verified and altered
     * @throws SdJwtVerificationException if the verification failed
     */
    public void validateAndSetHeader(SdJwt sdJwt) throws SdJwtVerificationException {
        headerValidator.validateandSetHeader(sdJwt);
    }

    /**
     * Validates the signature of the JWT, ensuring the key is hosted on an acceptable registry
     * @param sdJwt the sd-jwt to be verified
     * @param issuerJWK the issuer's key resolved from the DID Document
     * @throws SdJwtVerificationException if the signature or claims are invalid
     */
    public void validateAndSetJwt(SdJwt sdJwt, JWK issuerJWK) throws SdJwtVerificationException {
        signatureValidator.validateAndSetClaims(sdJwt, issuerJWK);
    }

    /**
     * Validates the Key Binding JWT of the SD-JWT, ensuring that it is fresh
     * and intended the correct audience accoding to RFC 9901 7.3 Key Binding Verification
     * This function should only be called if a key binding proof is required.
     * @param sdJwt the full validated SD-JWT
     * @param audience the audience (SD-JWT Verifier) for which the Key Binding should be issued
     * @param nonce the nonce which should be included in the Key Binding
     * @param acceptableKeyBindingWindow the acceptable window in seconds for the key binding, ensuring its freshness
     * @throws SdJwtVerificationException if no Key Binding is found or the key binding is not valid
     */
    public void validateKeyBinding(SdJwt sdJwt, String audience, String nonce, int acceptableKeyBindingWindow) throws SdJwtVerificationException {
        keyBindingValidator.validate(sdJwt, audience, nonce, acceptableKeyBindingWindow);
    }

    /**
     * Validates the time-based JWT claims ({@code exp} and {@code nbf}) using Nimbus
     * with a fixed clock skew tolerance.
     *
     * <p>The {@code iss} claim is intentionally <em>ignored</em> (not verified, not forbidden)
     * per swiss-profile-vc 1.0. {@code exp} and {@code nbf} are checked when present.</p>
     *
     * @param jwtString the compact serialized JWT
     * @throws ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException if {@code exp} or {@code nbf} are violated
     */
    public void validateTimeClaims(String jwtString) {
        timeClaimsValidator.validate(jwtString);
    }

    /**
     * Processes disclosures for the verification case according to RFC 9901 7.1
     * @param sdJwt the sd-jwt to be processed
     * @return the claims resolved and processed accordingto RFC 9901 as JSON
     * @throws SdJwtVerificationException if the sd-jwt did not pass verification and MUST be rejected
     */
    public Map<String, Object> processDisclosures(SdJwt sdJwt) throws SdJwtVerificationException {
        return disclosureProcessor.process(sdJwt);
    }
}
