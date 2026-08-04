package ch.admin.bj.swiyu.jweutil;

/**
 * Immutable size limits for {@link JweUtil#decrypt(String, com.nimbusds.jose.jwk.JWK, JweDecryptionLimits)}.
 */
public record JweDecryptionLimits(int maxCompressedCipherTextLength, int maxDecompressedPayloadLength) {

    /**
     * Default compressed-ciphertext limit: 20 MiB
     * Must accommodate the max VC batch size (20 MB), as high-entropy data (signatures) compresses poorly.
     */
    public static final int DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH = 20 * 1024 * 1024;

    /** Default decompressed-payload limit: 20 MiB (max batch size per swiss-profile-issuance 1.0). */
    public static final int DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH = 20 * 1024 * 1024;

    /**
     * @return a {@code JweDecryptionLimits} instance using the recommended default values.
     */
    public static JweDecryptionLimits defaults() {
        return new JweDecryptionLimits(DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH, DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH);
    }
}
