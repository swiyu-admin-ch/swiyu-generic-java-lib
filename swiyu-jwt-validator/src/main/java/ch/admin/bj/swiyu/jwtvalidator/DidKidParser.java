package ch.admin.bj.swiyu.jwtvalidator;

import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidKt;
import ch.admin.eid.didresolver.DidResolveException;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;

/**
 * Parses the {@code kid} header from a JWT and extracts the corresponding DID.
 *
 * <p>Enforces the security rule that JWTs must carry an <em>absolute</em> {@code kid}
 * (i.e. a fully-qualified DID URL that includes a {@code #} fragment).
 * Any JWT that is missing the {@code kid} is rejected immediately – no signature
 * verification is attempted. Validation of whether the {@code kid} is a valid absolute
 * DID URL is delegated to {@code getDidFromAbsoluteKid(kid)} of the
 * {@code didresolver} native library.</p>
 *
 * <p>Uses the {@code didresolver} native library ({@code ch.admin.swiyu:didresolver})
 * directly for two pure-computation operations: {@code getDidFromAbsoluteKid(kid)} and
 * {@code Did.getUrl()} – both require no network call.</p>
 *
 * <p>Kept as a separate injectable class so that {@link DidJwtValidator} can be fully
 * unit-tested without the native runtime binaries.</p>
 */
@Slf4j
public class DidKidParser {

    /**
     * Extracts the {@code kid} from the JWT JOSE header.
     *
     * @param jwtString the compact serialized JWT; must not be {@code null}
     * @return the {@code kid} value from the header
     * @throws JwtValidatorException if the JWT cannot be parsed or the {@code kid} header is absent
     */
    public String extractKidFromHeader(String jwtString) {
        if (jwtString == null || jwtString.isBlank()) {
            throw new JwtValidatorException("JWT string must not be null or blank");
        }
        SignedJWT signedJwt;
        try {
            signedJwt = SignedJWT.parse(jwtString);
        } catch (ParseException e) {
            throw new JwtValidatorException("Failed to parse JWT", e);
        }

        String kid = signedJwt.getHeader().getKeyID();
        if (kid == null || kid.isBlank()) {
            throw new JwtValidatorException("JWT is missing the 'kid' header – validation rejected");
        }
        log.debug("Extracted kid from JWT header: {}", kid);
        return kid;
    }

    /**
     * Extracts the DID string from an absolute {@code kid}.
     *
     * <p>Delegates to the resolver's {@code getDidFromAbsoluteKid} function to ensure
     * correct and consistent parsing without manual string splitting.</p>
     *
     * @param kid the absolute kid value (must contain a {@code #} fragment)
     * @return the DID string (e.g. {@code did:tdw:...}) without the key fragment
     * @throws JwtValidatorException if the resolver cannot parse the DID from the kid
     */
    public String getDidFromAbsoluteKid(String kid) {
        try (Did did = DidKt.getDidFromAbsoluteKid(kid)) {
            String didString = did.asString();
            log.debug("Resolved DID '{}' from kid '{}'", didString, kid);
            return didString;
        } catch (DidResolveException e) {
            throw new JwtValidatorException("Cannot extract DID from kid: " + kid, e);
        }
    }
}
