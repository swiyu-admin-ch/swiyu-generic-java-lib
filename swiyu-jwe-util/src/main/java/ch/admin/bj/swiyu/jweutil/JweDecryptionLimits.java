package ch.admin.bj.swiyu.jweutil;

/**
 * Immutable size limits for {@link JweUtil#decrypt(String, com.nimbusds.jose.jwk.JWK, JweDecryptionLimits)}.
 * <p>
 * Fixes the "JWE Decompression Bomb" vulnerability (EIDOMNI-1117 / EIDSEC-843): Nimbus only limits
 * the <em>compressed</em> ciphertext size before decompression, so a generous
 * {@code maxCompressedCipherTextLength} alone does not bound the decompressed size (DEFLATE allows
 * ratios up to ~1032:1). This type adds a second, independent limit on the decompressed payload,
 * checked right after decryption (not a streaming limit, since Nimbus offers no such hook).
 * <p>
 * Both values are validated fail-fast against a library-enforced absolute maximum in the
 * constructor, throwing {@link IllegalArgumentException} on misconfiguration.
 *
 * @param maxCompressedCipherTextLength max length (bytes) of the compressed ciphertext
 * @param maxDecompressedPayloadLength  max length (chars) of the decompressed payload
 */
public record JweDecryptionLimits(int maxCompressedCipherTextLength, int maxDecompressedPayloadLength) {

    /** Default compressed-ciphertext limit: 2 MiB (DCET recommendation). */
    public static final int DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH = 2_097_152;

    /** Default decompressed-payload limit: 10 MiB (max VC size per ADR-038). */
    public static final int DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH = 10_485_760;

    /** Absolute maximum for {@link #maxCompressedCipherTextLength()}: 5 MiB. */
    public static final int ABSOLUTE_MAX_COMPRESSED_CIPHER_TEXT_LENGTH = 5_242_880;

    /** Absolute maximum for {@link #maxDecompressedPayloadLength()}: 50 MiB. */
    public static final int ABSOLUTE_MAX_DECOMPRESSED_PAYLOAD_LENGTH = 52_428_800;

    /**
     * Validates the supplied limits, failing fast at construction time instead of at request time.
     *
     * @throws IllegalArgumentException if any value is {@code <= 0} or exceeds its absolute maximum
     */
    public JweDecryptionLimits {
        if (maxCompressedCipherTextLength <= 0) {
            throw new IllegalArgumentException(
                    "maxCompressedCipherTextLength must be > 0 but was " + maxCompressedCipherTextLength);
        }
        if (maxCompressedCipherTextLength > ABSOLUTE_MAX_COMPRESSED_CIPHER_TEXT_LENGTH) {
            throw new IllegalArgumentException(
                    "maxCompressedCipherTextLength must not exceed the absolute maximum of "
                            + ABSOLUTE_MAX_COMPRESSED_CIPHER_TEXT_LENGTH + " bytes but was "
                            + maxCompressedCipherTextLength);
        }
        if (maxDecompressedPayloadLength <= 0) {
            throw new IllegalArgumentException(
                    "maxDecompressedPayloadLength must be > 0 but was " + maxDecompressedPayloadLength);
        }
        if (maxDecompressedPayloadLength > ABSOLUTE_MAX_DECOMPRESSED_PAYLOAD_LENGTH) {
            throw new IllegalArgumentException(
                    "maxDecompressedPayloadLength must not exceed the absolute maximum of "
                            + ABSOLUTE_MAX_DECOMPRESSED_PAYLOAD_LENGTH + " characters but was "
                            + maxDecompressedPayloadLength);
        }
    }

    /**
     * @return a {@code JweDecryptionLimits} instance using the recommended default values.
     */
    public static JweDecryptionLimits defaults() {
        return new JweDecryptionLimits(DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH, DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH);
    }
}
