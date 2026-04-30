package ch.admin.bj.swiyu.jwtvalidator;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DidKidParser}.
 * <p>
 * Tests focus on JWT parsing and {@code kid} header validation logic.
 * The {@link DidKidParser#getDidFromAbsoluteKid(String)} method requires the native
 * didresolver library and is not covered here (tested via integration test).
 * </p>
 */
class DidKidParserTest {

    private static final String ABSOLUTE_KID =
            "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pHN1f7iLTaU6p7SBms:identifier.admin.ch#key-01";

    private DidKidParser parser;
    private ECKey ecKey;

    @BeforeEach
    void setUp() throws Exception {
        parser = new DidKidParser();
        ecKey = new ECKeyGenerator(Curve.P_256).keyID(ABSOLUTE_KID).generate();
    }

    // -------------------------------------------------------------------------
    // extractKidFromHeader – happy path
    // -------------------------------------------------------------------------

    @Test
    void extractKidFromHeader_withAbsoluteKid_returnsKid() throws Exception {
        String jwt = buildJwt(ABSOLUTE_KID);
        assertEquals(ABSOLUTE_KID, parser.extractKidFromHeader(jwt));
    }

    // -------------------------------------------------------------------------
    // extractKidFromHeader – rejection cases
    // -------------------------------------------------------------------------

    @Test
    void extractKidFromHeader_withMissingKid_throwsJwtValidatorException() throws Exception {
        String jwt = buildJwtWithoutKid();
        JwtValidatorException ex = assertThrows(
                JwtValidatorException.class, () -> parser.extractKidFromHeader(jwt));
        assertTrue(ex.getMessage().contains("missing the 'kid'"));
    }

    @Test
    void extractKidFromHeader_withNonAbsoluteKid_returnsKidAsIs() throws Exception {
        // extractKidFromHeader only checks for presence of kid, not whether it is absolute.
        // Rejection of non-absolute kids (without '#' fragment) is delegated to
        // getDidFromAbsoluteKid() via the native didresolver library (covered by integration test).
        String jwt = buildJwt("key-01");
        assertEquals("key-01", parser.extractKidFromHeader(jwt));
    }

    @Test
    void extractKidFromHeader_withMalformedJwt_throwsJwtValidatorException() {
        assertThrows(JwtValidatorException.class,
                () -> parser.extractKidFromHeader("this.is.not.a.jwt"));
    }

    @Test
    void extractKidFromHeader_withNullJwt_throwsJwtValidatorException() {
        assertThrows(JwtValidatorException.class,
                () -> parser.extractKidFromHeader(null));
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String buildJwt(String kid) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(kid)
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test")
                .issuer("https://issuer.example.com")
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecKey);
        jwt.sign(signer);
        return jwt.serialize();
    }

    private String buildJwtWithoutKid() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("test").build();
        SignedJWT jwt = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecKey);
        jwt.sign(signer);
        return jwt.serialize();
    }
}

