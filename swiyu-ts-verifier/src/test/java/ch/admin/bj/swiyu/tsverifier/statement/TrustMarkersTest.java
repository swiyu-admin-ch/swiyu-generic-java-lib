package ch.admin.bj.swiyu.tsverifier.statement;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class TrustMarkersTest {

    private TrustMarkers create(boolean identity, boolean compliant, boolean transparent, boolean governedUseCase, boolean governedUseCaseAuth) {
        return new TrustMarkers(identity, compliant, transparent, governedUseCase, governedUseCaseAuth);
    }

    @Test
    void testAllTrueIssuerAndVerifierTrusted() {
        TrustMarkers tm = create(true, true, true, true, true);
        assertThat(tm.isTrustedIssuer())
                .as("Issuer should be trusted when all markers are true")
                .isTrue();
        assertThat(tm.isTrustedVerifier())
                .as("Verifier should be trusted when all markers are true")
                .isTrue();
    }

    @Test
    void testIdentityMarkerFalse() {
        TrustMarkers tm = create(false, true, true, true, true);
        assertThat(tm.isTrustedIssuer())
                .as("Issuer should not be trusted when identity marker is false")
                .isFalse();
        assertThat(tm.isTrustedVerifier())
                .as("Verifier should not be trusted when identity marker is false")
                .isFalse();
    }

    @Test
    void testCompliantMarkerFalse() {
        TrustMarkers tm = create(true, false, true, true, true);
        assertThat(tm.isTrustedIssuer())
                .as("Issuer should not be trusted when compliant marker is false")
                .isFalse();
        assertThat(tm.isTrustedVerifier())
                .as("Verifier should not be trusted when compliant marker is false")
                .isFalse();
    }

    @Test
    void testTransparentMarkerFalseVerifierNotTrusted() {
        TrustMarkers tm = create(true, true, false, true, true);
        assertThat(tm.isTrustedIssuer())
                .as("Issuer should be trusted when transparent marker is false (does not exist for issuers)")
                .isTrue();
        assertThat(tm.isTrustedVerifier())
                .as("Verifier should not be trusted when transparent marker is false")
                .isFalse();
    }

    @Test
    void testGovernedUseCaseUnauthorized() {
        // governedUseCase = false, governedUseCaseAuthorization = true -> governed trust marker false
        TrustMarkers tm = create(true, true, true, true, false);
        assertThat(tm.isTrustedIssuer())
                .as("Issuer should not be trusted when governed markers are unequal")
                .isFalse();
        assertThat(tm.isTrustedVerifier())
                .as("Verifier should not be trusted when governed markers are unequal")
                .isFalse();
    }

    /**
     * Test when not governed use case the governed use case auth should not matter
     */
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testNotGovernedUseCase(boolean governedUseCaseAuth) {
        // both governed markers false => isGovernedTrustMarker true
        TrustMarkers tmIssuer = create(true, true, false, false, governedUseCaseAuth);
        assertThat(tmIssuer.isTrustedIssuer())
                .as("Issuer should be trusted when governed markers are both false (equal)")
                .isTrue();
        TrustMarkers tmVerifier = create(true, true, true, false, governedUseCaseAuth);
        assertThat(tmVerifier.isTrustedVerifier())
                .as("Verifier should not be trusted when transparent marker is false")
                .isTrue();
    }
}