package ch.admin.bj.swiyu.dpop;

import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for hashing and validating DPoP-related claims.
 * <p>
 * Provides static methods for computing SHA-256 hashes and validating the 'ath' (access token hash) claim
 * in DPoP JWTs.
 * </p>
 */
@UtilityClass
public final class DpopHashUtil {

    /**
     * Computes the base64url-encoded SHA-256 hash of the ASCII encoding of the input string.
     *
     * @param input the input string to hash
     * @return the base64url-encoded SHA-256 hash
     * @throws IllegalStateException if the SHA-256 algorithm is not available
     */
    public static String sha256(@NonNull String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] inputBytes = input.getBytes(StandardCharsets.US_ASCII);
            byte[] hashBytes = digest.digest(inputBytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Validates that the provided DPoP access token hash matches the expected access token value.
     *
     * @param expectedAccessToken the expected access token value
     * @param dpopAccessTokenHash the 'ath' claim from the DPoP JWT
     * @throws DpopValidationException if the hash does not match
     */
    public static void validateAccessTokenHash(String expectedAccessToken, String dpopAccessTokenHash) {
        if (expectedAccessToken == null || dpopAccessTokenHash == null ) {
            throw new DpopValidationException("Access token may not be null");
        }
        // Remove padding to prevent mismatches due to padding issues
        var accessTokenHashNoPadding = dpopAccessTokenHash.replace("=","");
        if (!sha256(expectedAccessToken).equals(accessTokenHashNoPadding)) {
            throw new DpopValidationException("Access token mismatch. ath must be base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value");
        }
    }
}
