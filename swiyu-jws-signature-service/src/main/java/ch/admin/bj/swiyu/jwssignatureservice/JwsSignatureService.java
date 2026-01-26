package ch.admin.bj.swiyu.jwssignatureservice;


import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import ch.admin.bj.swiyu.jwssignatureservice.factory.KeyManagementStrategyFactory;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

/**
 * This service is used to create a signer for the given signature configuration.
 * It uses the KeyManagementStrategyFactory to create the signer based on the key management method.
 * <p>
 * The signer is cached to avoid creating it multiple times.
 */
@Service
@AllArgsConstructor
public class JwsSignatureService {

    private static final String MAPPER_IS_NOT_INITIALIZED = "ObjectMapper is not initialized";
    private static final String FAILED_TO_COPY_SIGNATURE_CONFIGURATION = "Failed to copy signature configuration";
    private final KeyManagementStrategyFactory strategyFactory;

    private final ObjectMapper objectMapper;

    /**
     * Default constructor for JwsSignatureService.
     * Required for frameworks and serialization.
     */
    public JwsSignatureService() {
        this.strategyFactory = null;
        this.objectMapper = null;
    }

    /**
     * Creates a JWS signer with optional overridden keyId and keyPin.
     *
     * @param signatureConfigurationDto the signature configuration
     * @param keyId optional key ID override
     * @param keyPin optional key PIN override
     * @return a JWSSigner instance
     * @throws KeyStrategyException if signer creation fails
     */
    public JWSSigner createSigner(@NotNull SignatureConfigurationDto signatureConfigurationDto, @Nullable String keyId, @Nullable String keyPin) throws KeyStrategyException {
        try {
            if (objectMapper == null) {
                throw new KeyStrategyException(MAPPER_IS_NOT_INITIALIZED);
            }
            // Deep copy of Signature Configuration, so that we do not override the defaults
            var config = objectMapper.readValue(objectMapper.writeValueAsString(signatureConfigurationDto), SignatureConfigurationDto.class);
            if (StringUtils.isNotEmpty(keyId)) {
                config.getHsm().setKeyId(keyId);
            }
            if (StringUtils.isNotEmpty(keyPin)) {
                config.getHsm().setKeyPin(keyPin);
            }
            return buildSigner(config);
        } catch (JsonProcessingException e) {
            throw new KeyStrategyException(FAILED_TO_COPY_SIGNATURE_CONFIGURATION, e);
        }
    }

    /**
     * Creates a JWS signer.
     *
     * @param signatureConfigurationDto the signature configuration
     * @return a JWSSigner instance
     * @throws KeyStrategyException if signer creation fails
     */
    public JWSSigner createSigner(@NotNull SignatureConfigurationDto signatureConfigurationDto) throws KeyStrategyException {
        try {
            if (objectMapper == null) {
                throw new KeyStrategyException(MAPPER_IS_NOT_INITIALIZED);
            }
            // Deep copy of Signature Configuration, so that we do not override the defaults
            var config = objectMapper.readValue(objectMapper.writeValueAsString(signatureConfigurationDto), SignatureConfigurationDto.class);
            return buildSigner(config);
        } catch (JsonProcessingException e) {
            throw new KeyStrategyException(FAILED_TO_COPY_SIGNATURE_CONFIGURATION, e);
        }
    }

    private JWSSigner buildSigner(SignatureConfigurationDto signatureConfigurationDto) throws KeyStrategyException {
        if (strategyFactory == null) {
            throw new KeyStrategyException("KeyManagementStrategyFactory is not initialized");
        }
        return strategyFactory
                .getStrategy(signatureConfigurationDto.getKeyManagementMethod())
                .createSigner(signatureConfigurationDto);
    }
}