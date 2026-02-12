package ch.admin.bj.swiyu.jweutil;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import lombok.experimental.UtilityClass;

/**
 * Service for JSON Web Encryption (JWE) operations in the Swiyu ecosystem.
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
     * Decrypts the given JWE string.
     *
     * @param jweString           JWE as a String
     * @param recipientPrivateKey Empfänger-Privater Schlüssel (ECKey)
     * @return Klartext-Payload
     */
    public static String decrypt(String jweString, JWK recipientPrivateKey) {
        try {
            if (!(recipientPrivateKey instanceof ECKey ecKey)) {
                throw new JweUtilException("Only EC keys are supported.");
            }
            JWEObject jweObject = JWEObject.parse(jweString);
            jweObject.decrypt(new ECDHDecrypter(ecKey));
            return jweObject.getPayload().toString();
        } catch (Exception e) {
            throw new JweUtilException("Error during JWE decryption", e);
        }
    }
}
