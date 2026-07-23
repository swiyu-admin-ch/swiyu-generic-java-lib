package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.nimbusds.jose.JWSAlgorithm;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;

public class KeyStrategyTest {

    KeyStrategy strategy;
    SignatureConfigurationDto conf;

    @BeforeEach
    void setup() {
        strategy = new KeyStrategy();
        conf = mock(SignatureConfigurationDto.class);
    }

    /**
     * Load different support PEM keys
     * @param pemKey
     */
    @ParameterizedTest
    @ValueSource(strings = {""" 
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIEAjKKHHDj/RGhts2win4ZyScHPcTd6PAIKEDAosYTzy
            -----END PRIVATE KEY-----""" // Ed25519 Key
            , """
            -----BEGIN EC PRIVATE KEY-----
            MHQCAQEEIEOjv/xZqbNCSwZ3harrh9ytWKMQIEgoCTitcEGb359uoAcGBSuBBAAK
            oUQDQgAEyeN7GcF/CakfEsabrqVEI6TIsYYhPtEmVZ4ymZtjY6cauPqNPuV3DuT9
            05uB0lAOew7wfB99g2y+2QcncC8yYg==
            -----END EC PRIVATE KEY-----
            """ // EC P-256 Key
        })
    void testCreateSigner(String pemKey) {
        when(conf.getPrivateKey()).thenReturn(pemKey);
        var signer = assertDoesNotThrow(() -> strategy.createSigner(conf));
        var supportedJWSAlgorithms = signer.supportedJWSAlgorithms();
        
        
        assertThat(supportedJWSAlgorithms).isNotEmpty();
        if (supportedJWSAlgorithms.contains(JWSAlgorithm.ES256)) {
            assertThat(supportedJWSAlgorithms).doesNotContain(JWSAlgorithm.Ed25519);
        } else if (supportedJWSAlgorithms.contains(JWSAlgorithm.Ed25519)) {
            assertThat(supportedJWSAlgorithms).doesNotContain(JWSAlgorithm.ES256);
        }
    }
}
