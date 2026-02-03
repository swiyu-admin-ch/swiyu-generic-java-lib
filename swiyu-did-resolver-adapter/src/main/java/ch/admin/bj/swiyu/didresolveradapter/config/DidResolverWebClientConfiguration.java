package ch.admin.bj.swiyu.didresolveradapter.config;

import ch.admin.bj.swiyu.didresolveradapter.DidResolverWebClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

/**
 * Auto-configuration for the DidResolverWebClient bean.
 * <p>
 * Provides a {@link DidResolverWebClient} instance configured with a {@link RestClient.Builder}.
 * This configuration ensures that a RestClient-based DID resolver is available as a Spring bean
 * for dependency injection in applications using this library.
 * </p>
 */
@AutoConfiguration
@ConditionalOnClass(RestClient.class)
public class DidResolverWebClientConfiguration {

    /**
     * Default constructor for DidResolverWebClientConfiguration.
     * Required for frameworks and serialization.
     */
    public DidResolverWebClientConfiguration() {
        // Default constructor
    }

    /**
     * Creates a {@link DidResolverWebClient} bean using the provided {@link RestClient.Builder}.
     * <p>
     * The {@code WebClient.Builder} is automatically provided by Spring Boot when WebFlux is on the classpath.
     * This allows for flexible configuration and reuse of the RestClient instance.
     * </p>
     *
     * @param restClientBuilder the RestClient.Builder provided by Spring Boot
     * @return a configured DidResolverWebClient instance
     */
    @Bean
    @ConditionalOnMissingBean(DidResolverWebClient.class)
    public DidResolverWebClient didResolverWebClient(RestClient.Builder restClientBuilder) {
        return new DidResolverWebClient(restClientBuilder);
    }
}
