package ch.admin.bj.swiyu.didresolveradapter;

import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Jwk;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.didresolver.DidResolveException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientResponseException;

import java.text.ParseException;
import java.util.Map;


/**
 * Adapter for resolving Decentralized Identifier (DID) Documents and related data.
 * <p>
 * This service provides methods to load DID Documents, resolve trust statements, and extract public keys
 * from DID Documents using a RestClient-based resolver. It acts as a bridge between the DID resolution logic
 * and the HTTP/RestClient infrastructure, handling mapping, error handling, and conversion to standard formats.
 * </p>
 * <p>
 * Typical usage involves calling {@link #resolveDid(String, Map)}, {@link #resolveTrustStatement(String, String, Map)},
 * or {@link #resolveKey(String, Map)} to retrieve DID Documents, trust statements, or public keys, respectively.
 * </p>
 */
@Service
@AllArgsConstructor
@Slf4j
public class DidResolverAdapter {

    private final DidResolverWebClient didResolverWebClient;
    private final ObjectMapper objectMapper;

    /**
     * Resolves and returns the DID Document for the given DID identifier.
     *
     * @param didId the identifier of the DID Document
     * @param urlMappings optional URL mappings for rewriting the DID URL (can be null or empty)
     * @return the resolved {@link DidDoc} for the given DID
     * @throws DidResolverException if resolution fails or the DID is invalid
     * @throws IllegalArgumentException if didId is null
     */
    public DidDoc resolveDid(String didId, Map<String, String> urlMappings) throws DidResolverException {
        if (didId == null) {
            throw new IllegalArgumentException("did must not be null");
        }
        try (var did = new Did(didId)) {
            String didUrl = did.getUrl();
            String didLog = didResolverWebClient.retrieveDidDocument(didUrl, urlMappings);
            return did.resolve(didLog);
        } catch (Exception e) {
            throw new DidResolverException(e);
        }
    }

    /**
     * Retrieves the Trust Statement Verifiable Credential for the given DID from the trust registry.
     * <p>
     * Returns {@code null} only if the trust registry responds with HTTP 404 (statement not found).
     * Any other failure results in a {@link DidResolverException} that wraps the underlying cause.
     * </p>
     *
     * @param trustRegistryUrl the base URL of the trust registry issuance endpoint
     * @param vct the Verifiable Credential Type (schema ID) to query for
     * @param urlMappings optional URL mappings for rewriting the trust registry URL (can be null or empty)
     * @return the Trust Statement VC as a JSON string, or null if the trust registry returns HTTP 404
     * @throws DidResolverException if the trust registry responds with any status other than HTTP 404 or the request fails
     */
    public String resolveTrustStatement(String trustRegistryUrl, String vct, Map<String, String> urlMappings) {
        try {
            return didResolverWebClient.retrieveTrustStatement(trustRegistryUrl, vct, urlMappings);
        } catch (RestClientResponseException e) {
            HttpStatusCode status = e.getStatusCode();
            if (status == HttpStatus.NOT_FOUND) {
                log.info("Trust statement not found for {} {} (status: {})", trustRegistryUrl, vct, status);
                return null;
            }
            if (status.is5xxServerError()) {
                log.error("Trust registry error for {} {} (status: {})", trustRegistryUrl, vct, status, e);
            } else {
                log.warn("Trust statement retrieval failed for {} {} (status: {})", trustRegistryUrl, vct, status, e);
            }
            throw new DidResolverException("Failed retrieving trust statement", e);
        }
    }

    /**
     * Resolves and returns the JWK (public key) for the given key identifier from the DID Document.
     *
     * @param keyId the key identifier (DID fragment)
     * @param urlMappings optional URL mappings for rewriting the DID URL (can be null or empty)
     * @return the resolved {@link JWK} for the given keyId
     * @throws IllegalArgumentException if the keyId is malformed
     * @throws DidResolverException if the key cannot be resolved from the DID Document
     */
    public JWK resolveKey(String keyId, Map<String, String> urlMappings) {
        var didLog = fetchDidLog(keyId , urlMappings);
        DidDoc didDoc = getDidDoc(keyId, didLog);

        var keySplit = keyId.split("#");
        if (keySplit.length != 2) {
            throw new IllegalArgumentException(String.format("Key %s is malformed: missing fragment", keyId));
        }

        try {
            var jwk = didDoc.getKey(keySplit[1]);
            return didResolverJwkToNimbusJwk(jwk);
        } catch (DidSidekicksException e) {
            throw new DidResolverException(String.format("Key %s not found in DID Document", keyId), e);
        } catch (JsonProcessingException | ParseException e) {
            throw new DidResolverException(String.format("Verification Method %s is malformed", keyId), e);
        }
    }

    /**
     * Fetches the DID log (raw DID Document JSON) for the given key identifier.
     *
     * @param keyId the key identifier
     * @param urlMappings optional URL mappings for rewriting the DID URL
     * @return the raw DID Document JSON string
     * @throws DidResolverException if the DID Document could not be fetched
     */
    private String fetchDidLog(String keyId, Map<String, String> urlMappings) {
        try (var did = new Did(keyId)) {
            log.debug(did.getUrl());
            // Fetch the did log; throw RestClientResponseException if status >=400
            return didResolverWebClient.retrieveDidDocument(did.getUrl(), urlMappings);
        } catch (DidResolveException e) {
            throw new DidResolverException("DID Document could not be fetched", e);
        }
    }

    /**
     * Parses the DID Document from the given DID log string.
     *
     * @param keyId the key identifier
     * @param didLog the raw DID Document JSON string
     * @return the parsed {@link DidDoc}
     * @throws DidResolverException if the DID Document could not be loaded
     */
    private DidDoc getDidDoc(String keyId, String didLog) {
        DidDoc didDoc;
        try (Did did = new Did(keyId)) {
            didDoc = did.resolve(didLog);
        } catch (DidResolveException e) {
            throw new DidResolverException("DID Document could not be loaded", e);
        }
        return didDoc;
    }

    /**
     * Converts a resolver JWK to a Nimbus JWK instance.
     *
     * @param resolverJwk the JWK from the resolver
     * @return the parsed {@link JWK}
     * @throws JsonProcessingException if the JWK cannot be serialized
     * @throws ParseException if the JWK string cannot be parsed
     */
    private JWK didResolverJwkToNimbusJwk(Jwk resolverJwk) throws JsonProcessingException, ParseException {
        var jwkString = objectMapper.writeValueAsString(resolverJwk);
        return JWK.parse(jwkString);
    }

}