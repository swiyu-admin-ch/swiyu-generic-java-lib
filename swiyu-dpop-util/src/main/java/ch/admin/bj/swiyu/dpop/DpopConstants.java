package ch.admin.bj.swiyu.dpop;

import java.util.List;

/**
 * Constants and defaults for DPoP validation.
 * <p>
 * Provides standard values for DPoP JWT header and payload claims, supported algorithms, and other
 * configuration used throughout the DPoP validation process.
 * </p>
 */
public final class DpopConstants {

    /**
     * The required 'typ' header value for DPoP JWTs.
     */
    public static final String DPOP_JWT_HEADER_TYP = "dpop+jwt";

    /**
     * Supported algorithms for DPoP JWT signatures.
     */
    public static final List<String> SUPPORTED_ALGORITHMS = List.of("ES256");

    /**
     * Mandatory header claims for DPoP JWTs.
     */
    public static final List<String> MANDATORY_HEADER_CLAIMS = List.of("typ", "alg", "jwk");

    /**
     * Mandatory payload claims for DPoP JWTs.
     */
    public static final List<String> MANDATORY_PAYLOAD_CLAIMS = List.of("jti", "htm", "htu", "iat", "nonce");

    /**
     * Private constructor to prevent instantiation.
     */
    private DpopConstants() {
    }
}
