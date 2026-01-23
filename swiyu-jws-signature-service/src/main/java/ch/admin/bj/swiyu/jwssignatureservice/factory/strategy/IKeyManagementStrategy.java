package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;

import java.security.Provider;
import java.security.interfaces.ECPrivateKey;

/**
 * Interface for key management strategies used to create JWS signers.
 * Provides default methods for EC key-based signing with various providers.
 */
@FunctionalInterface
public interface IKeyManagementStrategy {
    /**
     * Creates a JWS signer based on the provided signature configuration.
     *
     * @param signatureConfigurationDto the signature configuration
     * @return a JWSSigner instance
     * @throws KeyStrategyException if signer creation fails
     */
    JWSSigner createSigner(SignatureConfigurationDto signatureConfigurationDto) throws KeyStrategyException;

    /**
     * Creates a signer from an ECKey and a security provider.
     *
     * @param privateKey The private key loaded with ECKey.load from the keystore
     * @param provider   Provider like Sun PKCS11 Provider, already used to initialize the keystore
     * @return a newly created Signing Support
     * @throws JOSEException if the Signer could not be created with the provided key &amp; provider
     */
    default JWSSigner fromEC(ECKey privateKey, Provider provider) throws JOSEException {
        var signer = new ECDSASigner(privateKey);
        signer.getJCAContext().setProvider(provider);
        return signer;
    }

    /**
     * Creates a signer from an ECPrivateKey and a security provider (for HSM use).
     *
     * @param privateKey The private key loaded from the keystore. The keystore must have a certificate for it to work properly.
     * @param provider   Provider like Securosys Primus Provider, already used to initialize the keystore
     * @return a newly created Signing Support
     * @throws JOSEException if the Signer could not be created with the provided key &amp; provider
     */
    default JWSSigner fromEC(ECPrivateKey privateKey, Provider provider) throws JOSEException {
        var signer = new ECDSASigner(privateKey);
        signer.getJCAContext().setProvider(provider);
        return signer;
    }

    /**
     * Creates a signer from an ECKey using the BouncyCastle provider.
     *
     * @param privateKey The private key loaded with ECKey.load from a string using bouncycastle
     * @return a newly created Signing Support
     * @throws JOSEException if the Signer could not be created with the provided key &amp; provider
     */
    default JWSSigner fromEC(ECKey privateKey) throws JOSEException {
        return fromEC(privateKey, BouncyCastleProviderSingleton.getInstance());
    }
}