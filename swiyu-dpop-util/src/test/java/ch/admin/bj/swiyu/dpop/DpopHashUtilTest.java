package ch.admin.bj.swiyu.dpop;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DpopHashUtilTest {

    @Test
    void sha256_base64UrlEncoding_matchesKnownVector() {
        String hash = DpopHashUtil.sha256("abc");
        assertEquals("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0=", hash);
    }

    @Test
    void validateAccessTokenHash_matches_expected() {
        String accessToken = "abc";
        String ath = DpopHashUtil.sha256(accessToken);
        DpopHashUtil.validateAccessTokenHash(accessToken, ath);
    }

    @Test
    void validateAccessTokenHash_mismatch_throws() {
        assertThrows(DpopValidationException.class,
                () -> DpopHashUtil.validateAccessTokenHash("abc", "wrong"));
    }
}

