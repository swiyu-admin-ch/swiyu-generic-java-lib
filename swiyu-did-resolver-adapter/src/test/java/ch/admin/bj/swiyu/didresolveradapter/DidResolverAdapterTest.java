package ch.admin.bj.swiyu.didresolveradapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DidResolverAdapterTest {
    private DidResolverWebClient didResolverWebClient;
    private DidResolverAdapter didResolverAdapter;
    private ObjectMapper objectMapper;

    // Example DID and DID log from integration environment (valid format)
    private static final String DID = "did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212";
    private static final String DID_LOG_VALID = "[\"1-QmdJiFHQ3gHMyRUnW6Rri6hHwKRrQUJadBRoirLZUJtsmC\",\"2025-01-31T09:35:11Z\",{\"method\":\"did:tdw:0.3\",\"scid\":\"QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ\",\"updateKeys\":[\"z6MkrU7wPQwBXsnYzWVJMWbvq61ZeDib6v9aQ3DpXu7qWagv\"]},{\"value\":{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/suites/jws-2020/v1\"],\"id\":\"did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212\",\"authentication\":[\"did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212#auth-key-01\"],\"assertionMethod\":[\"did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212#assert-key-01\"],\"verificationMethod\":[{\"id\":\"did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212#auth-key-01\",\"controller\":\"did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"D3nYTvdvNL0wRvm4bu92CjntEpDfI8bfQdQhaaD6Qv8\",\"y\":\"oLe56pmgQWmhAo5eviw2XFNHjmGhepy9RzQSseUXGIU\",\"kid\":\"auth-key-01\"}},{\"id\":\"did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212#assert-key-01\",\"controller\":\"did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"1fwnwoN8zatr6kD_bvwY2zQDV4D6blE7mzTliQF11Jc\",\"y\":\"9-cDZlPqXVlJnE0rcUUyy7P_15x7RLE-jiNGqHA9FP4\",\"kid\":\"assert-key-01\"}}]}},[{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"created\":\"2025-01-31T09:35:11Z\",\"verificationMethod\":\"did:key:z6MkrU7wPQwBXsnYzWVJMWbvq61ZeDib6v9aQ3DpXu7qWagv#z6MkrU7wPQwBXsnYzWVJMWbvq61ZeDib6v9aQ3DpXu7qWagv\",\"proofPurpose\":\"authentication\",\"challenge\":\"1-QmdJiFHQ3gHMyRUnW6Rri6hHwKRrQUJadBRoirLZUJtsmC\",\"proofValue\":\"z2HuP8d1Wk6mLZpp2QmxywGNSDAi2CxfgoE7FJoeB1DSfUfg2kUyokAaea1Bqz5Q6L5FaukkD1KdxUpU45z1TUB3R\"}]]";

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        didResolverWebClient = mock(DidResolverWebClient.class);
        didResolverAdapter = new DidResolverAdapter(didResolverWebClient, objectMapper);
    }

    @Test
    void validDidResolving() {
        when(didResolverWebClient.retrieveDidDocument(anyString(), anyMap())).thenReturn(DID_LOG_VALID);
        var didDoc = didResolverAdapter.resolveDid(DID, Map.of());
        assertThat(didDoc.getId()).isEqualTo(DID);
    }

    @Test
    void validDidResolvingWithMapping() {
        Map<String, String> mapping = Map.of("https://identifier-reg.trust-infra.swiyu-int.admin.ch", "https://test.replacement");
        when(didResolverWebClient.retrieveDidDocument(anyString(), eq(mapping))).thenReturn(DID_LOG_VALID);
        var didDoc = didResolverAdapter.resolveDid(DID, mapping);
        assertThat(didDoc.getId()).isEqualTo(DID);
    }

    @Test
    void invalidDidThrowsException() {
        assertThatThrownBy(() -> didResolverAdapter.resolveDid(null, Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void resolveKey_success() {
        when(didResolverWebClient.retrieveDidDocument(anyString(), anyMap())).thenReturn(DID_LOG_VALID);
        var jwk = didResolverAdapter.resolveKey(DID + "#assert-key-01", Map.of());
        assertThat(jwk.getKeyID()).isEqualTo("assert-key-01");
    }

    @Test
    void resolveKey_missingJwk_throwsException() {
        when(didResolverWebClient.retrieveDidDocument(anyString(), anyMap())).thenReturn(DID_LOG_VALID);
        assertThatThrownBy(() -> didResolverAdapter.resolveKey(DID + "#non-existent-key", Map.of()))
                .isInstanceOf(DidResolverException.class)
                .hasMessageContaining("non-existent-key");
    }

    @Test
    void resolveTrustStatement_success() {
        String trustRegistryUrl = "https://trust-registry.example.com";
        String vct = "VerifiableCredentialType";
        String trustStatement = "{\"vc\":true}";
        when(didResolverWebClient.retrieveTrustStatement(eq(trustRegistryUrl), eq(vct), anyMap())).thenReturn(trustStatement);
        String result = didResolverAdapter.resolveTrustStatement(trustRegistryUrl, vct, Map.of());
        assertThat(result).isEqualTo(trustStatement);
    }

    @Test
    void resolveTrustStatement_notFound_returnsNull() {
        String trustRegistryUrl = "https://trust-registry.example.com";
        String vct = "VerifiableCredentialType";
        when(didResolverWebClient.retrieveTrustStatement(eq(trustRegistryUrl), eq(vct), anyMap()))
                .thenThrow(WebClientResponseException.create(404, "Not Found", null, null, StandardCharsets.UTF_8));
        String result = didResolverAdapter.resolveTrustStatement(trustRegistryUrl, vct, Map.of());
        assertThat(result).isNull();
    }
}
