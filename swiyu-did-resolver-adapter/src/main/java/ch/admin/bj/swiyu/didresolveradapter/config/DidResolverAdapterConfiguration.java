package ch.admin.bj.swiyu.didresolveradapter.config;

import ch.admin.bj.swiyu.didresolveradapter.DidResolverAdapter;
import ch.admin.bj.swiyu.didresolveradapter.DidResolverWebClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for the DidResolverAdapter bean.
 * <p>
 * Provides a {@link DidResolverAdapter} instance configured with a {@link DidResolverWebClient}
 * and a {@link ObjectMapper}. This configuration ensures that a DID resolver adapter is available
 * as a Spring bean for dependency injection in applications using this library.
 * </p>
 */
@AutoConfiguration
@ConditionalOnClass({DidResolverAdapter.class, DidResolverWebClient.class, ObjectMapper.class})
public class DidResolverAdapterConfiguration {

    /**
     * Default constructor for DidResolverAdapterConfiguration.
     * Required for frameworks and serialization.
     */
    public DidResolverAdapterConfiguration() {
        // Default constructor
    }

    /**
     * Creates a {@link DidResolverAdapter} bean using the provided {@link DidResolverWebClient} and {@link ObjectMapper}.
     * <p>
     * The {@code DidResolverWebClient} and {@code ObjectMapper} are automatically provided by Spring Boot
     * and other configuration classes. This allows for flexible configuration and reuse of the adapter instance.
     * </p>
     *
     * @param didResolverWebClient the WebClient-based DID resolver
     * @param objectMapper the Jackson object mapper
     * @return a configured DidResolverAdapter instance
     */
    @Bean
    @ConditionalOnMissingBean(DidResolverAdapter.class)
    public DidResolverAdapter didResolverAdapter(
            DidResolverWebClient didResolverWebClient,
            ObjectMapper objectMapper
    ) {
        return new DidResolverAdapter(didResolverWebClient, objectMapper);
    }
}
