package ch.admin.bj.swiyu.sdjwtverifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.authlete.sd.Disclosure;
import com.nimbusds.jwt.JWTClaimsSet;

import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Unit tests for {@link SdJwtDisclosureProcessor} (RFC 9901 §7.1 entry point).
 *
 * <p>The recursive tree-walking itself is covered in detail by {@link SdJwtNodeProcessorTest};
 * this test focuses on the processor's own responsibilities: wiring claims + disclosures,
 * rejecting duplicate/unused disclosures, and enforcing the {@code _sd_alg} requirement.</p>
 *
 * <p>Note: {@code sdJwt} is a Mockito mock, so {@code setResolvedClaims}/{@code getResolvedClaims}
 * are not linked to each other as they would be on the real {@link SdJwt}; the resolved claims
 * are therefore captured via {@link ArgumentCaptor} instead of relying on the processor's return value.</p>
 */
class SdJwtDisclosureProcessorTest {

    private final SdJwtDisclosureProcessor processor = new SdJwtDisclosureProcessor();
    private SdJwt sdJwt;

    @BeforeEach
    void setUp() {
        sdJwt = mock(SdJwt.class);
    }

    @Test
    void process_whenDisclosureMatchesDigestAndAlgIsCorrect_thenResolvesClaimsAndStripsSdKeys() throws SdJwtVerificationException {
        Disclosure disclosure = new Disclosure("name", "Bob");
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder()
                .claim("_sd", List.of(disclosure.digest()))
                .claim("_sd_alg", "sha-256")
                .build());
        when(sdJwt.getDisclosures()).thenReturn(List.of(disclosure));

        processor.process(sdJwt);

        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(sdJwt).setResolvedClaims(captor.capture());
        assertThat(captor.getValue()).containsEntry("name", "Bob").doesNotContainKey("_sd").doesNotContainKey("_sd_alg");
    }

    @Test
    void process_whenDisclosuresAreNotDistinct_thenThrows() {
        Disclosure disclosure = new Disclosure("name", "Bob");
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder()
                .claim("_sd", List.of(disclosure.digest()))
                .build());
        when(sdJwt.getDisclosures()).thenReturn(List.of(disclosure, disclosure));

        assertThatThrownBy(() -> processor.process(sdJwt))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("non-distinct");
    }

    @Test
    void process_whenDisclosureIsNotReferencedByAnyDigest_thenThrows() {
        Disclosure unusedDisclosure = new Disclosure("name", "Bob");
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder().build());
        when(sdJwt.getDisclosures()).thenReturn(List.of(unusedDisclosure));

        assertThatThrownBy(() -> processor.process(sdJwt))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("Unused disclosures");
    }

    @Test
    void process_whenSdAlgIsNotSha256_thenThrows() {
        Disclosure disclosure = new Disclosure("name", "Bob");
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder()
                .claim("_sd", List.of(disclosure.digest()))
                .claim("_sd_alg", "sha-1")
                .build());
        when(sdJwt.getDisclosures()).thenReturn(List.of(disclosure));

        assertThatThrownBy(() -> processor.process(sdJwt))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("Unsupported _sd_alg value");
    }
}
