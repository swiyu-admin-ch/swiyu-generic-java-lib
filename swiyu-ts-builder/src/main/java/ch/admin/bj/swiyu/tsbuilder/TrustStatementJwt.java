package ch.admin.bj.swiyu.tsbuilder;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents an unsigned Trust Statement JWT, consisting of a JOSE header and a payload.
 * <p>
 * This class acts as the product of the builder pipeline. It accumulates header and payload claims
 * and exposes a serialized form of the payload ready to be signed by a {@code JWSSigner}.
 * </p>
 */
public final class TrustStatementJwt {

    private final Map<String, String> header;
    private final Map<String, Object> payload;

    /**
     * Creates an empty {@code TrustStatementJwt} with no claims.
     */
    public TrustStatementJwt() {
        this.header = new LinkedHashMap<>();
        this.payload = new LinkedHashMap<>();
    }

    /**
     * Adds or replaces a claim in the JOSE header.
     *
     * @param key   the header claim name, must not be {@code null}
     * @param value the header claim value, must not be {@code null}
     */
    public void addHeaderClaim(String key, String value) {
        // TODO
    }

    /**
     * Adds or replaces a claim in the JWT payload.
     *
     * @param key   the payload claim name, must not be {@code null}
     * @param value the payload claim value, must not be {@code null}
     */
    public void addPayloadClaim(String key, Object value) {
        // TODO
    }

    /**
     * Returns an unmodifiable view of the JOSE header claims.
     *
     * @return the header claims
     */
    public Map<String, String> getHeader() {
        return Collections.unmodifiableMap(header);
    }

    /**
     * Returns an unmodifiable view of the JWT payload claims.
     *
     * @return the payload claims
     */
    public Map<String, Object> getPayload() {
        return Collections.unmodifiableMap(payload);
    }

    /**
     * Serializes the JWT header and payload into the unsigned compact form
     * ({@code BASE64URL(header).BASE64URL(payload)}) that a {@code JWSSigner} must sign.
     *
     * @return the unsigned payload string ready for signing
     */
    public String getPayloadToSign() {
        // TODO
        return null;
    }
}

