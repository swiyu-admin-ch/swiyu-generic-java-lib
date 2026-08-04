package ch.admin.bj.swiyu.jweutil;

/**
 * Immutable size limits for {@link JweUtil#decrypt(String, com.nimbusds.jose.jwk.JWK, JweDecryptionLimits)}.
 * <p>
 * Fixes the "JWE Decompression Bomb" vulnerability (EIDOMNI-1117 / EIDSEC-843): Nimbus only limits
 * the <em>compressed</em> ciphertext size before decompression, so a generous
 * {@code maxCompressedCipherTextLength} alone does not bound the decompressed size (DEFLATE allows
 * ratios up to ~1032:1). This type adds a second, independent limit on the decompressed payload,
 * checked right after decryption
 * <p>
 * Both values are validated fail-fast against a library-enforced absolute maximum in the
 * constructor, throwing {@link IllegalArgumentException} on misconfiguration.
 *
 * @param maxCompressedCipherTextLength max length (bytes) of the compressed ciphertext
 * @param maxDecompressedPayloadLength  max length (chars) of the decompressed payload
 */
public record JweDecryptionLimits(int maxCompressedCipherTextLength, int maxDecompressedPayloadLength) {

    /**
     * Default compressed-ciphertext limit: 20 MiB
     * Must accommodate the max VC batch size (20 MB), as high-entropy data (signatures) compresses poorly.
     */
    public static final int DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH = 20 * 1024 * 1024;

    /** Default decompressed-payload limit: 20 MiB (max batch size per swiss-profile-issuance 1.0). */
    public static final int DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH = 20 * 1024 * 1024;

    /** Absolute maximum for compressed ciphertext: 30 MiB. */
    public static final int ABSOLUTE_MAX_COMPRESSED_CIPHER_TEXT_LENGTH = 30 * 1024 * 1024;

    /** Absolute maximum for decompressed payload: 50 MiB. */
    public static final int ABSOLUTE_MAX_DECOMPRESSED_PAYLOAD_LENGTH = 50 * 1024 * 1024;

    /**
     * Validates the supplied limits, failing fast at construction time instead of at request time.
     *S
     * @throws IllegalArgumentException if any value is {@code <= 0} or exceeds its absolute maximum
     */
    public JweDecryptionLimits {
        requireInRange(maxCompressedCipherTextLength, 1, ABSOLUTE_MAX_COMPRESSED_CIPHER_TEXT_LENGTH, "maxCompressedCipherTextLength");
        requireInRange(maxDecompressedPayloadLength, 1, ABSOLUTE_MAX_DECOMPRESSED_PAYLOAD_LENGTH, "maxDecompressedPayloadLength");
    }

    private static void requireInRange(int value, int min, int max, String fieldName) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(
                    String.format("%s must be between %d and %d but was %d", fieldName, min, max, value)
            );
        }
    }

    /**
     * @return a {@code JweDecryptionLimits} instance using the recommended default values.
     */
    public static JweDecryptionLimits defaults() {
        return new JweDecryptionLimits(DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH, DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH);
    }
}
