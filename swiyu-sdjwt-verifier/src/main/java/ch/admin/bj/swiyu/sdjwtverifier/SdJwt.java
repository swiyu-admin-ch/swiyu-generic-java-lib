package ch.admin.bj.swiyu.sdjwtverifier;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.authlete.sd.Disclosure;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

/**
 * The class models a selective disclosure JSON Web Token (SD-JWT) w.r.t.
 * <a href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4">RFC 9901 ("Selective Disclosure for JSON Web Tokens")</a>
 */
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public class SdJwt {
    private final SignedJWT jwt;
    private final String[] parts;
    @Setter(value = AccessLevel.PACKAGE)
    private JWSHeader header;
    @Setter(value = AccessLevel.PACKAGE)
    private JWTClaimsSet claims;
    @Setter(value = AccessLevel.PACKAGE)
    private Map<String, Object> resolvedClaims;

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4.3">Key Binding JWT</a>
     */
    private final Optional<String> keyBinding;

    private final String presentationHash;

    public boolean hasKeyBinding() {
        return keyBinding.isPresent();
    }

    public List<Disclosure> getDisclosures() {
        int disclosureLength = getParts().length;
        if (hasKeyBinding()) {
            // Last entry in parts is key binding
            disclosureLength -= 1;
        }
        return Arrays.stream(Arrays.copyOfRange(getParts(), 1, disclosureLength))
                .map(Disclosure::parse).toList();
    }

    /**
     * only available after being set during validation
     * @return the header of the jwt part of the sd-jwt
     */
    public JWSHeader getHeader() {
        if (header == null) {
            throw new IllegalStateException("header has not yet been verified");
        }
        return header;
    }

    /**
     * Only available after being set during validation
     * @return the claim set of the jwt part of the sd-jwt
     */
    public JWTClaimsSet getClaims() {
        if (claims == null) {
            throw new IllegalStateException("claims has not yet been verified");
        }
        return claims;
    }

    /**
     * The first Part of the SD-JWT is the JWT part a SD-JWT 
     * @return The JWT in the compact serialized format
     */
    public String getSerializedJWT() {
        return parts[0];
    }

}
