package ch.admin.bj.swiyu.jwssignatureservice.config;

import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.factory.KeyManagementStrategyFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for the JwsSignatureService bean.
 * Provides a JwsSignatureService instance configured with the required dependencies.
 */
@AutoConfiguration
public class JwsSignatureServiceConfiguration {

    /**
     * Default constructor for JwsSignatureServiceConfiguration.
     * Required for frameworks and serialization.
     */
    public JwsSignatureServiceConfiguration() {
        // Default constructor
    }

    /**
     * Creates a JwsSignatureService bean.
     *
     * @param keyManagementStrategyFactory the factory for key management strategies
     * @param objectMapper the Jackson object mapper
     * @return a configured JwsSignatureService instance
     */
    @Bean
    public JwsSignatureService jwsSignatureService(KeyManagementStrategyFactory keyManagementStrategyFactory,
                                                   ObjectMapper objectMapper) {
        return new JwsSignatureService(keyManagementStrategyFactory, objectMapper);
    }
}
