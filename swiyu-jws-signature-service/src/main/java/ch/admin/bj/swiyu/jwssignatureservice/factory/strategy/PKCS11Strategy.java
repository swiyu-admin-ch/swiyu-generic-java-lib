package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * This strategy is used for a PKCS #11 (Cryptoki) connection to an HSM.
 * A pkcs11 module (implementation for how the hardware is to be used) and configuration
 * (settings of this implementation) must be provided va pkcs11Config. These two things are vendor specific.
 * It requires the key to be available together with a self-signed certificate on the HSM.
 */
@Component("pkcs11")
public class PKCS11Strategy implements IKeyManagementStrategy {
    /**
     * Default constructor for PKCS11Strategy.
     * Required for frameworks and serialization.
     */
    public PKCS11Strategy() {
    }

    /**
     * Creates a signer using a PKCS#11 HSM provider and keystore.
     *
     * @param signatureConfigurationDto the signature configuration
     * @return a JWSSigner instance
     * @throws KeyStrategyException if key loading or signer creation fails
     */
    @Override
    public JWSSigner createSigner(SignatureConfigurationDto signatureConfigurationDto) throws KeyStrategyException {
        try {
            Provider provider = Security.getProvider("SunPKCS11").configure(signatureConfigurationDto.getHsm().getPkcs11Config());
            Security.addProvider(provider);
            var hsmKeyStore = KeyStore.getInstance("PKCS11", provider);
            hsmKeyStore.load(null, signatureConfigurationDto.getHsm().getUserPin().toCharArray());
            var privateKey = ECKey.load(hsmKeyStore, signatureConfigurationDto.getHsm().getKeyId(), signatureConfigurationDto.getHsm().getUserPin().toCharArray());

            return fromEC(privateKey, provider);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | JOSEException e) {
            throw new KeyStrategyException("Failed to load EC Key from PKCS11 JCE.", e);
        }
    }
}