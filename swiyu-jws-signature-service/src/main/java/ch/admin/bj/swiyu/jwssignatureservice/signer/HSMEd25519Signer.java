package ch.admin.bj.swiyu.jwssignatureservice.signer;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class HSMEd25519Signer implements JWSSigner{
    private final EdECPrivateKey privateKey;
    private final Provider provider;
	private final JCAContext jcaContext = new JCAContext();

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }
    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        try {
            Signature signer = Signature.getInstance("EdDSA", provider);
            signer.initSign(privateKey);
            signer.update(signingInput);
            byte[] signature = signer.sign();
            return Base64URL.encode(signature);
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new JOSEException("Failed to sign with HSM ED25519 key due to: " + e.getMessage(), e);
        }
    }
    
    
}
