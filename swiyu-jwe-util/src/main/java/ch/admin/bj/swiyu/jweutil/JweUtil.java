package ch.admin.bj.swiyu.jweutil;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.opts.MaxCompressedCipherTextLength;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import lombok.experimental.UtilityClass;

import java.text.ParseException;
import java.util.Set;

/**
 * Utility for JSON Web Encryption (JWE) operations in the Swiyu ecosystem.
 * <p>
 * This class provides a placeholder for future JWE encryption and decryption functionality.
 * It is intended to offer methods for encrypting and decrypting payloads using JWE standards.
 * </p>
 * <p>
 * Note: This is a stub and does not contain any real implementation yet.
 * </p>
 */
@UtilityClass
public class JweUtil {

    /**
     * Encrypts the given payload using JWE.
     *
     * @param payload The data to encrypt (as a String).
     * @return The encrypted JWE string, or null if not implemented.
     */
    public static String encrypt(String payload, JWK recipientPublicKey) {
        try {
            if (!(recipientPublicKey instanceof ECKey ecKey)) {
                throw new JweUtilException("Only EC keys are supported.");
            }
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                    .compressionAlgorithm(CompressionAlgorithm.DEF)
                    .keyID(ecKey.getKeyID())
                    .build();
            JWEObject jweObject = new JWEObject(header, new Payload(payload));
            jweObject.encrypt(new ECDHEncrypter(ecKey));
            return jweObject.serialize();
        } catch (Exception e) {
            throw new JweUtilException("Error during JWE encryption", e);
        }
    }

    /**
     * Decrypts the given JWE string using {@link JweDecryptionLimits#defaults()}.
     *
     * @deprecated Use {@link #decrypt(String, JWK, JweDecryptionLimits)} instead (EIDOMNI-1117 / EIDSEC-843).
     */
    @Deprecated(since = "2.1.0")
    public static String decrypt(String jweString, JWK recipientPrivateKey) {
        return decrypt(jweString, recipientPrivateKey, JweDecryptionLimits.defaults());
    }

    /**
     * Decrypts the given JWE string.
     *
     * @param maxCompressedCipherTextLength max length for compressed ciphertexts; default (if null or {@code <= 0})
     *                                      is {@link JweDecryptionLimits#DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH}.
     * @deprecated Use {@link #decrypt(String, JWK, JweDecryptionLimits)} instead. This overload does not enforce
     *             a decompressed-payload limit, part of the fix for EIDOMNI-1117 / EIDSEC-843.
     */
    @Deprecated(since = "2.1.0")
    public static String decrypt(String jweString, JWK recipientPrivateKey, Integer maxCompressedCipherTextLength) {
        int compressedLimit = (maxCompressedCipherTextLength != null && maxCompressedCipherTextLength > 0)
                ? maxCompressedCipherTextLength
                : JweDecryptionLimits.DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH;
        return decrypt(jweString, recipientPrivateKey,
                new JweDecryptionLimits(compressedLimit, JweDecryptionLimits.DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH));
    }

    /**
     * Decrypts the given JWE string, enforcing the supplied size limits.
     * <p>
     * Fixes the JWE "Decompression Bomb" vulnerability (EIDOMNI-1117 / EIDSEC-843): Nimbus only checks the
     * compressed ciphertext size before decompression, so this method additionally checks the length of the
     * already decompressed payload before returning it (post-hoc check, not a streaming limit).
     *
     * @param jweString           JWE as a String
     * @param recipientPrivateKey private key (ECKey) of the recipient
     * @param limits the size limits to enforce; if {@code null}, {@link JweDecryptionLimits#defaults()} is used
     * @throws JweUtilException if decryption fails, e.g. because a limit is exceeded
     */
    public static String decrypt(String jweString, JWK recipientPrivateKey, JweDecryptionLimits limits) {
        JweDecryptionLimits effectiveLimits = limits != null ? limits : JweDecryptionLimits.defaults();

        Set<JWEDecrypterOption> options = Set.of(
                new MaxCompressedCipherTextLength(effectiveLimits.maxCompressedCipherTextLength())
        );

        try {
            if (!(recipientPrivateKey instanceof ECKey ecKey)) {
                throw new JweUtilException("Only EC keys are supported.");
            }

            JWEObject jweObject = JWEObject.parse(jweString);
            jweObject.decrypt(new ECDHDecrypter(ecKey), options);

            String payload = jweObject.getPayload().toString();
            if (payload.length() > effectiveLimits.maxDecompressedPayloadLength()) {
                throw new JweUtilException(String.format(
                        "Decrypted payload exceeds the maximum allowed decompressed size of %d characters",
                        effectiveLimits.maxDecompressedPayloadLength()
                ));
            }
            return payload;

        } catch (ParseException | JOSEException e) {
            throw new JweUtilException("Error during JWE decryption", e);
        }
    }
}
