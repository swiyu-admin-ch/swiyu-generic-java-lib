package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Component;

/**
 * Key management strategy for ECKey-based signing.
 * Parses a PEM-encoded EC private key and creates a signer.
 */
@Component("key")
public class KeyStrategy implements IKeyManagementStrategy {
    /**
     * Default constructor for KeyStrategy.
     * Required for frameworks and serialization.
     */
    public KeyStrategy() {
    }

    /**
     * Creates a signer from a PEM-encoded EC private key.
     *
     * @param signatureConfigurationDto the signature configuration
     * @return a JWSSigner instance
     * @throws KeyStrategyException if key parsing or signer creation fails
     */
    @Override
    public JWSSigner createSigner(SignatureConfigurationDto signatureConfigurationDto) throws KeyStrategyException {
        try {
            PEMParser parser = new PEMParser(new StringReader(signatureConfigurationDto.getPrivateKey()));
            Object pemObj = parser.readObject();
            PrivateKey key = switch (pemObj) {
                case PrivateKeyInfo pemKey -> new JcaPEMKeyConverter().getPrivateKey(pemKey);
                case PEMKeyPair pemKey -> new JcaPEMKeyConverter().getKeyPair(pemKey).getPrivate();
                default -> throw new KeyStrategyException("Key could not be parsed");
                };
            return fromKeyReference(key, BouncyCastleProviderSingleton.getInstance());
        } catch (JOSEException | IOException e) {
            throw new KeyStrategyException("Failed to parse Key from PEM.", e);
        }
    }
}