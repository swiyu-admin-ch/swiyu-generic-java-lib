package ch.admin.bj.swiyu.jwssignatureservice;

import ch.admin.bj.swiyu.jwssignatureservice.dto.HSMPropertiesDto;
import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import ch.admin.bj.swiyu.jwssignatureservice.factory.KeyManagementStrategyFactory;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.IKeyManagementStrategy;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for JwsSignatureService.
 * Tests the creation of JWS signers with various configurations and error scenarios.
 */
class JwsSignatureServiceTest {

    private KeyManagementStrategyFactory strategyFactory;
    private ObjectMapper objectMapper;
    private JwsSignatureService service;
    private IKeyManagementStrategy mockStrategy;
    private JWSSigner mockSigner;

    @BeforeEach
    void setUp() {
        strategyFactory = mock(KeyManagementStrategyFactory.class);
        objectMapper = new ObjectMapper();
        mockStrategy = mock(IKeyManagementStrategy.class);
        mockSigner = mock(JWSSigner.class);
        service = new JwsSignatureService(strategyFactory, objectMapper);
    }

    /**
     * Tests that createSigner successfully creates a JWSSigner with basic configuration.
     */
    @Test
    @DisplayName("createSigner() successfully creates a signer with basic configuration")
    void createSigner_withBasicConfig_success() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto config = createBasicConfig();
        when(strategyFactory.getStrategy("key")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class))).thenReturn(mockSigner);

        // When
        JWSSigner result = service.createSigner(config);

        // Then
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(mockSigner);
        verify(strategyFactory).getStrategy("key");
        verify(mockStrategy).createSigner(any(SignatureConfigurationDto.class));
    }

    /**
     * Tests that createSigner with keyId and keyPin overrides successfully creates a signer with modified configuration.
     */
    @Test
    @DisplayName("createSigner() with keyId and keyPin overrides successfully creates a signer")
    void createSigner_withOverrides_success() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto config = createConfigWithHSM();
        String overrideKeyId = "override-key-id";
        String overrideKeyPin = "override-pin";

        when(strategyFactory.getStrategy("pkcs11")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class))).thenReturn(mockSigner);

        // When
        JWSSigner result = service.createSigner(config, overrideKeyId, overrideKeyPin);

        // Then
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(mockSigner);

        ArgumentCaptor<SignatureConfigurationDto> captor = ArgumentCaptor.forClass(SignatureConfigurationDto.class);
        verify(mockStrategy).createSigner(captor.capture());

        SignatureConfigurationDto capturedConfig = captor.getValue();
        assertThat(capturedConfig.getHsm().getKeyId()).isEqualTo(overrideKeyId);
        assertThat(capturedConfig.getHsm().getKeyPin()).isEqualTo(overrideKeyPin);
    }

    /**
     * Tests that null keyId does not override the original value in the configuration.
     */
    @Test
    @DisplayName("createSigner() with null keyId keeps original value")
    void createSigner_withNullKeyId_keepsOriginal() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto config = createConfigWithHSM();
        String originalKeyId = config.getHsm().getKeyId();

        when(strategyFactory.getStrategy("pkcs11")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class))).thenReturn(mockSigner);

        // When
        service.createSigner(config, null, "somePin");

        // Then
        ArgumentCaptor<SignatureConfigurationDto> captor = ArgumentCaptor.forClass(SignatureConfigurationDto.class);
        verify(mockStrategy).createSigner(captor.capture());

        SignatureConfigurationDto capturedConfig = captor.getValue();
        assertThat(capturedConfig.getHsm().getKeyId()).isEqualTo(originalKeyId);
    }

    /**
     * Tests that empty keyId does not override the original value in the configuration.
     */
    @Test
    @DisplayName("createSigner() with empty keyId keeps original value")
    void createSigner_withEmptyKeyId_keepsOriginal() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto config = createConfigWithHSM();
        String originalKeyId = config.getHsm().getKeyId();

        when(strategyFactory.getStrategy("pkcs11")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class))).thenReturn(mockSigner);

        // When
        service.createSigner(config, "", "somePin");

        // Then
        ArgumentCaptor<SignatureConfigurationDto> captor = ArgumentCaptor.forClass(SignatureConfigurationDto.class);
        verify(mockStrategy).createSigner(captor.capture());

        SignatureConfigurationDto capturedConfig = captor.getValue();
        assertThat(capturedConfig.getHsm().getKeyId()).isEqualTo(originalKeyId);
    }

    /**
     * Tests that null keyPin does not override the original value in the configuration.
     */
    @Test
    @DisplayName("createSigner() with null keyPin keeps original value")
    void createSigner_withNullKeyPin_keepsOriginal() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto config = createConfigWithHSM();
        String originalKeyPin = config.getHsm().getKeyPin();

        when(strategyFactory.getStrategy("pkcs11")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class))).thenReturn(mockSigner);

        // When
        service.createSigner(config, "someKeyId", null);

        // Then
        ArgumentCaptor<SignatureConfigurationDto> captor = ArgumentCaptor.forClass(SignatureConfigurationDto.class);
        verify(mockStrategy).createSigner(captor.capture());

        SignatureConfigurationDto capturedConfig = captor.getValue();
        assertThat(capturedConfig.getHsm().getKeyPin()).isEqualTo(originalKeyPin);
    }

    /**
     * Tests that createSigner throws KeyStrategyException when ObjectMapper is null.
     */
    @Test
    @DisplayName("createSigner() throws exception when ObjectMapper is null")
    void createSigner_withNullObjectMapper_throwsException() {
        // Given
        JwsSignatureService serviceWithNullMapper = new JwsSignatureService(strategyFactory, null);
        SignatureConfigurationDto config = createBasicConfig();

        // When/Then
        assertThatThrownBy(() -> serviceWithNullMapper.createSigner(config))
                .isInstanceOf(KeyStrategyException.class)
                .hasMessage("ObjectMapper is not initialized");
    }

    /**
     * Tests that createSigner with overrides throws KeyStrategyException when ObjectMapper is null.
     */
    @Test
    @DisplayName("createSigner() with overrides throws exception when ObjectMapper is null")
    void createSigner_withOverridesAndNullObjectMapper_throwsException() {
        // Given
        JwsSignatureService serviceWithNullMapper = new JwsSignatureService(strategyFactory, null);
        SignatureConfigurationDto config = createConfigWithHSM();

        // When/Then
        assertThatThrownBy(() -> serviceWithNullMapper.createSigner(config, "keyId", "keyPin"))
                .isInstanceOf(KeyStrategyException.class)
                .hasMessage("ObjectMapper is not initialized");
    }

    /**
     * Tests that createSigner throws KeyStrategyException when StrategyFactory is null.
     */
    @Test
    @DisplayName("createSigner() throws exception when StrategyFactory is null")
    void createSigner_withNullStrategyFactory_throwsException() {
        // Given
        JwsSignatureService serviceWithNullFactory = new JwsSignatureService(null, objectMapper);
        SignatureConfigurationDto config = createBasicConfig();

        // When/Then
        assertThatThrownBy(() -> serviceWithNullFactory.createSigner(config))
                .isInstanceOf(KeyStrategyException.class)
                .hasMessage("KeyManagementStrategyFactory is not initialized");
    }

    /**
     * Tests that createSigner propagates exceptions thrown by the strategy.
     */
    @Test
    @DisplayName("createSigner() throws exception when strategy throws exception")
    void createSigner_strategyThrowsException_propagatesException() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto config = createBasicConfig();
        when(strategyFactory.getStrategy("key")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class)))
                .thenThrow(new KeyStrategyException("Strategy failed"));

        // When/Then
        assertThatThrownBy(() -> service.createSigner(config))
                .isInstanceOf(KeyStrategyException.class)
                .hasMessage("Strategy failed");
    }

    /**
     * Tests that createSigner throws IllegalArgumentException for unsupported key management methods.
     */
    @Test
    @DisplayName("createSigner() throws exception when strategy factory throws IllegalArgumentException")
    void createSigner_unsupportedKeyManagement_throwsException() {
        // Given
        SignatureConfigurationDto config = SignatureConfigurationDto.builder()
                .keyManagementMethod("unsupported")
                .verificationMethod("did:example:123#key-1")
                .build();

        when(strategyFactory.getStrategy("unsupported"))
                .thenThrow(new IllegalArgumentException("Unsupported key management method: unsupported"));

        // When/Then
        assertThatThrownBy(() -> service.createSigner(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported key management method: unsupported");
    }

    /**
     * Tests that createSigner with overrides creates a deep copy and does not modify the original configuration.
     */
    @Test
    @DisplayName("createSigner() creates deep copy and does not modify original config")
    void createSigner_withOverrides_doesNotModifyOriginalConfig() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto originalConfig = createConfigWithHSM();
        String originalKeyId = originalConfig.getHsm().getKeyId();
        String originalKeyPin = originalConfig.getHsm().getKeyPin();
        String overrideKeyId = "new-key-id";
        String overrideKeyPin = "new-key-pin";

        when(strategyFactory.getStrategy("pkcs11")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class))).thenReturn(mockSigner);

        // When
        service.createSigner(originalConfig, overrideKeyId, overrideKeyPin);

        // Then - original config should remain unchanged
        assertThat(originalConfig.getHsm().getKeyId()).isEqualTo(originalKeyId);
        assertThat(originalConfig.getHsm().getKeyPin()).isEqualTo(originalKeyPin);
    }

    /**
     * Tests that createSigner works correctly with the Securosys HSM strategy.
     */
    @Test
    @DisplayName("createSigner() works correctly with securosys strategy")
    void createSigner_withSecurosysStrategy_success() throws KeyStrategyException {
        // Given
        SignatureConfigurationDto config = SignatureConfigurationDto.builder()
                .keyManagementMethod("securosys")
                .verificationMethod("did:example:123#key-1")
                .hsm(HSMPropertiesDto.builder()
                        .keyId("securosys-key")
                        .userPin("pin123")
                        .user("user")
                        .password("password")
                        .host("localhost")
                        .port("8080")
                        .build())
                .build();

        when(strategyFactory.getStrategy("securosys")).thenReturn(mockStrategy);
        when(mockStrategy.createSigner(any(SignatureConfigurationDto.class))).thenReturn(mockSigner);

        // When
        JWSSigner result = service.createSigner(config);

        // Then
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(mockSigner);
        verify(strategyFactory).getStrategy("securosys");
    }

    /**
     * Tests that the default constructor creates an instance with null fields.
     */
    @Test
    @DisplayName("default constructor creates instance with null fields")
    void defaultConstructor_createsInstanceWithNullFields() {
        // When
        JwsSignatureService defaultService = new JwsSignatureService();

        // Then
        assertThat(defaultService).isNotNull();

        // Attempting to use it should throw exception
        SignatureConfigurationDto config = createBasicConfig();
        assertThatThrownBy(() -> defaultService.createSigner(config))
                .isInstanceOf(KeyStrategyException.class);
    }

    // Helper methods

    private SignatureConfigurationDto createBasicConfig() {
        return SignatureConfigurationDto.builder()
                .keyManagementMethod("key")
                .privateKey("-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----")
                .verificationMethod("did:example:123#key-1")
                .build();
    }

    private SignatureConfigurationDto createConfigWithHSM() {
        return SignatureConfigurationDto.builder()
                .keyManagementMethod("pkcs11")
                .verificationMethod("did:example:123#key-1")
                .hsm(HSMPropertiesDto.builder()
                        .keyId("original-key-id")
                        .keyPin("original-pin")
                        .userPin("user-pin")
                        .pkcs11Config("/etc/pkcs11.cfg")
                        .build())
                .build();
    }
}

