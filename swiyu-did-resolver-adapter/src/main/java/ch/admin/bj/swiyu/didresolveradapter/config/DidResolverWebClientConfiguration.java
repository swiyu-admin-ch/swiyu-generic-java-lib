package ch.admin.bj.swiyu.didresolveradapter.config;

import ch.admin.bj.swiyu.didresolveradapter.DidResolverWebClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Auto-configuration for the DidResolverWebClient bean.
 * <p>
 * Provides a {@link DidResolverWebClient} instance configured with a {@link WebClient.Builder}.
 * This configuration ensures that a WebClient-based DID resolver is available as a Spring bean
 * for dependency injection in applications using this library.
 * </p>
 */
@AutoConfiguration
@ConditionalOnClass(WebClient.class)
public class DidResolverWebClientConfiguration {

    /**
     * Default constructor for DidResolverWebClientConfiguration.
     * Required for frameworks and serialization.
     */
    public DidResolverWebClientConfiguration() {
        // Default constructor
    }

    /**
     * Creates a {@link DidResolverWebClient} bean using the provided {@link WebClient.Builder}.
     * <p>
     * The {@code WebClient.Builder} is automatically provided by Spring Boot when WebFlux is on the classpath.
     * This allows for flexible configuration and reuse of the WebClient instance.
     * </p>
     *
     * @param webClientBuilder the WebClient.Builder provided by Spring Boot
     * @return a configured DidResolverWebClient instance
     */
    @Bean
    @ConditionalOnMissingBean(DidResolverWebClient.class)
    public DidResolverWebClient didResolverWebClient(WebClient.Builder webClientBuilder) {
        return new DidResolverWebClient(webClientBuilder);
    }
}
