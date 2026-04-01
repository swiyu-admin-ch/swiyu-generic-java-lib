package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Represents an unsigned Trust Statement JWT, consisting of a Nimbus {@link JWSHeader}
 * and a Nimbus {@link JWTClaimsSet}.
 * <p>
 * This class acts as the product of the builder pipeline. It is a thin, immutable wrapper
 * around the two Nimbus types that together form an unsigned JWT, ready to be signed by a
 * {@code JWSSigner}.
 * </p>
 * <p>
 * External consumers sign the statement by constructing a {@link com.nimbusds.jwt.SignedJWT}
 * directly from the exposed header and claims:
 * </p>
 * <pre>{@code
 * TrustStatementJwt ts = new IdTsBuilder()...build();
 * SignedJWT signed = new SignedJWT(ts.getJwsHeader(), ts.getClaimsSet());
 * signed.sign(signer);
 * String compact = signed.serialize();
 * }</pre>
 * <p>
 * Mutation methods are intentionally package-private: only builders within the same package
 * may assemble the header and claims.
 * </p>
 */
public final class TrustStatementJwt {

    private final JWSHeader jwsHeader;
    private final JWTClaimsSet claimsSet;

    /**
     * Creates a {@code TrustStatementJwt} from the fully assembled Nimbus header and claims.
     * <p>
     * Package-private: called exclusively by {@link AbstractTrustStatementBuilder#build()}.
     * </p>
     *
     * @param jwsHeader  the fully assembled JOSE header, must not be {@code null}
     * @param claimsSet  the fully assembled JWT claims set, must not be {@code null}
     */
    TrustStatementJwt(JWSHeader jwsHeader, JWTClaimsSet claimsSet) {
        this.jwsHeader = jwsHeader;
        this.claimsSet = claimsSet;
    }

    /**
     * Returns the Nimbus {@link JWSHeader} for this trust statement.
     * <p>
     * Pass this directly to {@link com.nimbusds.jwt.SignedJWT#SignedJWT(JWSHeader, JWTClaimsSet)}.
     * </p>
     *
     * @return the JOSE header
     */
    public JWSHeader getJwsHeader() {
        return jwsHeader;
    }

    /**
     * Returns the Nimbus {@link JWTClaimsSet} for this trust statement.
     * <p>
     * Pass this directly to {@link com.nimbusds.jwt.SignedJWT#SignedJWT(JWSHeader, JWTClaimsSet)}.
     * </p>
     *
     * @return the JWT claims set
     */
    public JWTClaimsSet getClaimsSet() {
        return claimsSet;
    }
}
