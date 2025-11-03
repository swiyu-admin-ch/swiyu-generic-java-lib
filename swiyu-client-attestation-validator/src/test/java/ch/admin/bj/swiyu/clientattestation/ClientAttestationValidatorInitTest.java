package ch.admin.bj.swiyu.clientattestation;


import ch.admin.bj.swiyu.clientattestation.config.AttestationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class ClientAttestationValidatorInitTest {

    private AttestationProperties props;

    @BeforeEach
    void setUp() {
        props = Mockito.mock(AttestationProperties.class, Mockito.RETURNS_DEEP_STUBS);
    }

    @Test
    @DisplayName("@PostConstruct init(): loads EC public key and ensures BC provider present")
    void init_loadsKey_success() throws Exception {
        KeyPair kp = genEcP256();
        String pem = toPublicPem(kp);
        Resource res = new ByteArrayResource(pem.getBytes(StandardCharsets.UTF_8));
        when(props.getPublicKeyPath()).thenReturn(res);
        when(props.isEnabled()).thenReturn(true);

        ClientAttestationValidator validator = new ClientAttestationValidator(props);

        assertThat(Security.getProvider("BC")).isNull(); // before init, optional

        validator.init();

        // BC provider should now be available
        assertThat(Security.getProvider("BC")).isNotNull();

        Object key = ReflectionTestUtils.getField(validator, "publicKey");
        assertThat(key).isInstanceOf(ECPublicKey.class);
        assertThat(((ECPublicKey) key).getW()).isNotNull();
    }

    @Test
    @DisplayName("@PostConstruct init(): invalid PEM → publicKey == null and BC provider present")
    void init_invalidPem_setsNullKey() {
        String invalidPem = "-----BEGIN PUBLIC KEY-----\nINVALID\n-----END PUBLIC KEY-----\n";
        Resource res = new ByteArrayResource(invalidPem.getBytes(StandardCharsets.UTF_8));
        when(props.getPublicKeyPath()).thenReturn(res);
        when(props.isEnabled()).thenReturn(true);

        ClientAttestationValidator validator = new ClientAttestationValidator(props);

        validator.init();

        // BC provider installed even if key load fails
        assertThat(Security.getProvider("BC")).isNotNull();

        Object key = ReflectionTestUtils.getField(validator, "publicKey");
        assertThat(key).isNull();
    }

    private static KeyPair genEcP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    private static String toPublicPem(KeyPair kp) {
        String base64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        }
        sb.append("-----END PUBLIC KEY-----\n");
        return sb.toString();
    }
}
