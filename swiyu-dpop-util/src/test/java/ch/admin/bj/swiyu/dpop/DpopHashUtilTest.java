package ch.admin.bj.swiyu.dpop;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DpopHashUtilTest {

    private static final String KNWON_VECTOR_ACCESS_TOKEN = "abc";
    private static final String KNOWN_VECTOR = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0=";

    @Test
    void sha256_base64UrlEncoding_matchesKnownVector() {
        String hash = DpopHashUtil.sha256(KNWON_VECTOR_ACCESS_TOKEN);
        assertEquals(KNOWN_VECTOR.replace("=", ""), hash);
    }

    @Test
    void validateAccessTokenHash_matches_expected() {
        String accessToken = KNWON_VECTOR_ACCESS_TOKEN;
        String ath = DpopHashUtil.sha256(accessToken);
        DpopHashUtil.validateAccessTokenHash(accessToken, ath);
    }

    @Test
    void validateAccessTokenHash_mismatch_throws() {
        assertThrows(DpopValidationException.class,
                () -> DpopHashUtil.validateAccessTokenHash(KNWON_VECTOR_ACCESS_TOKEN, "wrong"));
    }

    @Test
    void validatesKnownVectorWithPadding() {
        assertDoesNotThrow(() -> DpopHashUtil.validateAccessTokenHash(KNWON_VECTOR_ACCESS_TOKEN, KNOWN_VECTOR));
    }

    @Test
    void validateAccessTokenHash_doesNotThrowNullpointer() {
        assertThrows(DpopValidationException.class, () -> DpopHashUtil.validateAccessTokenHash(null, KNOWN_VECTOR));
        assertThrows(DpopValidationException.class, () -> DpopHashUtil.validateAccessTokenHash(KNWON_VECTOR_ACCESS_TOKEN, null));
        assertThrows(DpopValidationException.class, () -> DpopHashUtil.validateAccessTokenHash(null, null));
    }
}

