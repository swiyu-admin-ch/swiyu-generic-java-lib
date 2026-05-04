package ch.admin.bj.swiyu.sdjwtvalidator;

import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SdJwtParserTest {

    private static final String ISSUER_JWT = "header.payload.signature";

    private static final String DISCLOSURE_1 =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "[\"salt1\",\"given_name\",\"Max\"]".getBytes(StandardCharsets.UTF_8));
    private static final String DISCLOSURE_2 =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "[\"salt2\",\"family_name\",\"Muster\"]".getBytes(StandardCharsets.UTF_8));
    // A KB-JWT looks like a compact JWT (contains dots)
    private static final String KB_JWT = "kb-header.kb-payload.kb-signature";

    // -------------------------------------------------------------------------
    // extractIssuerSignedJwt
    // -------------------------------------------------------------------------

    @Test
    void extractIssuerSignedJwt_withDisclosures_returnsJwtPart() {
        String sdJwt = ISSUER_JWT + "~" + DISCLOSURE_1 + "~";
        assertEquals(ISSUER_JWT, SdJwtParser.extractIssuerSignedJwt(sdJwt));
    }

    @Test
    void extractIssuerSignedJwt_withKeyBinding_returnsJwtPart() {
        String sdJwt = ISSUER_JWT + "~" + DISCLOSURE_1 + "~" + KB_JWT;
        assertEquals(ISSUER_JWT, SdJwtParser.extractIssuerSignedJwt(sdJwt));
    }

    @Test
    void extractIssuerSignedJwt_withNoDisclosures_returnsJwtPart() {
        String sdJwt = ISSUER_JWT + "~";
        assertEquals(ISSUER_JWT, SdJwtParser.extractIssuerSignedJwt(sdJwt));
    }

    @Test
    void extractIssuerSignedJwt_withoutTilde_throwsJwtValidatorException() {
        assertThrows(JwtValidatorException.class,
                () -> SdJwtParser.extractIssuerSignedJwt(ISSUER_JWT));
    }

    @Test
    void extractIssuerSignedJwt_withNull_throwsJwtValidatorException() {
        assertThrows(JwtValidatorException.class,
                () -> SdJwtParser.extractIssuerSignedJwt(null));
    }

    @Test
    void extractIssuerSignedJwt_withBlank_throwsJwtValidatorException() {
        assertThrows(JwtValidatorException.class,
                () -> SdJwtParser.extractIssuerSignedJwt("   "));
    }

    // -------------------------------------------------------------------------
    // extractDisclosures
    // -------------------------------------------------------------------------

    @Test
    void extractDisclosures_withTwoDisclosures_returnsBoth() {
        String sdJwt = ISSUER_JWT + "~" + DISCLOSURE_1 + "~" + DISCLOSURE_2 + "~";
        List<String> disclosures = SdJwtParser.extractDisclosures(sdJwt);
        assertEquals(2, disclosures.size());
        assertTrue(disclosures.contains(DISCLOSURE_1));
        assertTrue(disclosures.contains(DISCLOSURE_2));
    }

    @Test
    void extractDisclosures_withNoDisclosures_returnsEmptyList() {
        String sdJwt = ISSUER_JWT + "~";
        assertTrue(SdJwtParser.extractDisclosures(sdJwt).isEmpty());
    }

    @Test
    void extractDisclosures_withKeyBinding_excludesKbJwt() {
        String sdJwt = ISSUER_JWT + "~" + DISCLOSURE_1 + "~" + KB_JWT;
        List<String> disclosures = SdJwtParser.extractDisclosures(sdJwt);
        assertEquals(1, disclosures.size());
        assertEquals(DISCLOSURE_1, disclosures.get(0));
    }

    // -------------------------------------------------------------------------
    // decodeDisclosure
    // -------------------------------------------------------------------------

    @Test
    void decodeDisclosure_validBase64url_returnsJsonString() {
        String json = SdJwtParser.decodeDisclosure(DISCLOSURE_1);
        assertEquals("[\"salt1\",\"given_name\",\"Max\"]", json);
    }

    @Test
    void decodeDisclosure_invalidBase64url_throwsJwtValidatorException() {
        assertThrows(JwtValidatorException.class,
                () -> SdJwtParser.decodeDisclosure("!!!not-base64!!!"));
    }
}

