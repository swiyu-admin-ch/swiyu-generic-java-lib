package ch.admin.bj.swiyu.jweutil;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.opts.MaxCompressedCipherTextLength;
import com.nimbusds.jose.crypto.opts.MaxDecompressedPlainTextLength;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import lombok.experimental.UtilityClass;

import java.util.Set;

/**
 * Utility for JSON Web Encryption (JWE) operations in the Swiyu ecosystem.
 * <p>
 * Provides JWE encryption and decryption functionality conforming to the Swiss Profile
 * for eID issuance (https://swiyu-admin-ch.github.io/specifications/swiss-profile-issuance/#cryptography):
 * <ul>
 *   <li>JWS algorithm MUST be ES256</li>
 *   <li>Encryption MUST use only ECDH-ES with P-256 Keys with A256GCM algorithm</li>
 *   <li>If zipping is possible, Deflate (DEF) MUST be used</li>
 *   <li>If using encryption is possible, it MUST be used</li>
 * </ul>
 */
@UtilityClass
public class JweUtil {

    /**
     * Encrypts the given payload using JWE according to the Swiss Profile.
     * <p>
     * The encryption uses the following parameters as mandated by the Swiss Profile:
     * <ul>
     *   <li>Algorithm: {@link JWEAlgorithm#ECDH_ES} (ECDH-ES)</li>
     *   <li>Encryption Method: {@link EncryptionMethod#A256GCM} (AES-256-GCM)</li>
     *   <li>Compression: {@link CompressionAlgorithm#DEF} (Deflate)</li>
     *   <li>Key Requirements: EC Key with P-256 curve ({@link Curve#P_256})</li>
     * </ul>
     * If the recipient public key has an algorithm ({@code alg}) set, it MUST be {@code ECDH-ES}.
     * The key MUST use the P-256 curve.
     *
     * @param payload The data to encrypt (as a String).
     * @param recipientPublicKey The recipient's public EC key (must be P-256 curve, alg must be ECDH-ES if set).
     * @return The encrypted JWE string in compact serialization.
     * @throws JweUtilException if the key is not an EC key, not P-256 curve, has an invalid algorithm,
     *                          or encryption fails.
     */
    public static String encrypt(String payload, JWK recipientPublicKey) {
        try {
            if (!(recipientPublicKey instanceof ECKey ecKey)) {
                throw new JweUtilException("Only EC keys are supported.");
            }

            // Ensure the key is valid and has a P-256 Curve according to Swiss Profile
            if (ecKey.getCurve() == null || !Curve.P_256.equals(ecKey.getCurve())) {
                throw new JweUtilException("Only P-256 curve is supported according to Swiss Profile.");
            }

            // Check algorithm if specified -> alg is optional so check only applies if set
            if (ecKey.getAlgorithm() != null && !JWEAlgorithm.ECDH_ES.equals(ecKey.getAlgorithm())) {
                throw new JweUtilException("Only ECDH-ES algorithm is supported according to Swiss Profile.");
            }

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                    .compressionAlgorithm(CompressionAlgorithm.DEF)
                    .keyID(ecKey.getKeyID())
                    .build();
            JWEObject jweObject = new JWEObject(header, new Payload(payload));
            jweObject.encrypt(new ECDHEncrypter(ecKey));
            return jweObject.serialize();
        } catch (JweUtilException e) {
            throw e;
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
                new MaxCompressedCipherTextLength(effectiveLimits.maxCompressedCipherTextLength()),
                new MaxDecompressedPlainTextLength(effectiveLimits.maxDecompressedPayloadLength())
        );

        try {
            if (!(recipientPrivateKey instanceof ECKey ecKey)) {
                throw new JweUtilException("Only EC keys are supported.");
            }

            JWEObject jweObject = JWEObject.parse(jweString);
            // Note: in nimbus jose-jwt it seems that the compressed size check is done in
            // JWEObject while decompressed size check in the decrypter.
            // --> options must be passed to both
            jweObject.decrypt(new ECDHDecrypter(ecKey, options), options);

            return jweObject.getPayload().toString();

        } catch (JweUtilException e) {
            throw e;
        } catch (JOSEException e) {
            throw new JweUtilException(e.getMessage(), e);
        } catch (Exception e) {
            throw new JweUtilException("Error during JWE decryption", e);
        }
    }
}
