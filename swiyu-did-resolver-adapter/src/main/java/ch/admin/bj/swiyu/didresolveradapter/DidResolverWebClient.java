package ch.admin.bj.swiyu.didresolveradapter;

import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;


/**
 * WebClient-based implementation for resolving Decentralized Identifier (DID) Documents and trust statements.
 * <p>
 * This adapter uses Spring's {@link WebClient} to load DID Documents and trust statements from remote endpoints.
 * It supports URL rewriting via mappings and is designed for use as a Spring bean.
 * </p>
 * <p>
 * Typical usage involves calling {@link #retrieveDidDocument(String, Map)} to fetch a DID Document
 * or {@link #retrieveTrustStatement(String, String, Map)} to fetch a trust statement VC from a trust registry.
 * </p>
 */
@Service
public class DidResolverWebClient {

    private final WebClient webClient;

    /**
     * Constructs a DidResolverWebClient using the provided {@link WebClient.Builder}.
     * <p>
     * The builder is automatically provided by Spring Boot when WebFlux is on the classpath.
     * </p>
     *
     * @param webClientBuilder the WebClient.Builder bean
     */
    public DidResolverWebClient(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    /**
     * Retrieves the DID Document as a string for the given DID URL.
     * <p>
     * The URL may be rewritten using the provided mappings. This method performs a synchronous HTTP GET
     * and returns the raw DID Document JSON as a string.
     * </p>
     *
     * @param didUrl the DID URL to resolve
     * @param urlMappings optional URL mappings for rewriting the DID URL (can be null or empty)
     * @return the DID Document as a JSON string
     * @throws org.springframework.web.reactive.function.client.WebClientResponseException if the HTTP request fails
     */
    public String retrieveDidDocument(String didUrl, Map<String, String> urlMappings) {
        return webClient.get()
                .uri(UrlRewriteHelper.getRewrittenUrl(didUrl, urlMappings))
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    /**
     * Retrieves the Trust Statement Verifiable Credential for the given DID from the trust registry.
     * <p>
     * This method queries a trust registry endpoint for a trust statement VC of a specific credential type (vct).
     * The trust registry URL may be rewritten using the provided mappings.
     * </p>
     *
     * @param trustRegistryIssuanceUrl the base URL of the trust registry issuance endpoint
     * @param vct the Verifiable Credential Type (schema ID) to query for
     * @param urlMappings optional URL mappings for rewriting the trust registry URL (can be null or empty)
     * @return the Trust Statement VC as a JSON string
     * @throws HttpClientErrorException if a 4xx error occurs
     * @throws HttpServerErrorException if a 5xx error occurs
     * @throws org.springframework.web.reactive.function.client.WebClientResponseException if the HTTP request fails
     */

    public String retrieveTrustStatement(String trustRegistryIssuanceUrl, String vct, Map<String, String> urlMappings)
            throws HttpClientErrorException, HttpServerErrorException {
        String rewrittenUrl = UrlRewriteHelper.getRewrittenUrl(trustRegistryIssuanceUrl, urlMappings);
        URI uri = UriComponentsBuilder.fromUriString(rewrittenUrl)
                .queryParam("vcSchemaId", vct)
                .build(true)
                .toUri();
        return webClient.get()
                .uri(uri)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }
}