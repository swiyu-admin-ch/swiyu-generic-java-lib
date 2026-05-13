package ch.admin.bj.swiyu.tsverifier.statement;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

/**
 * Container for the five trust‑markers.
 *
 * <p>Each field corresponds to a specific marker defined in the Trust Procotol 2.0
 * specification and is mapped to its JSON property name via {@link JsonProperty}.
 *
 * <ul>
 *   <li><strong>viTM</strong> – Identity Trust Marker
 *   <li><strong>caTM</strong> – Compliant Actor Trust Marker
 *   <li><strong>tvTM</strong> – Transparent Verification Trust Marker
 *   <li><strong>gucTM</strong> – Governed Use‑Case Trust Marker
 *   <li><strong>gucaTM</strong> – Governed Use‑Case Authorization Trust Marker
 * </ul>
 *
 */
@Builder
public record TrustMarkers(
        @JsonProperty("viTM")
        boolean identityTrustMarker,
        @JsonProperty("caTM")
        boolean compliantActorTrustMarker,
        @JsonProperty("tvTM")
        boolean transparentVerificationTrustMarker,
        @JsonProperty("gucTM")
        boolean governedUseCaseTrustMarker,
        @JsonProperty("gucaTM")
        boolean governedUseCaseAuthorizationTrustMarker
) {
    /**
     * Evaluates if an issuer is trustworthy.
     * @return true if the issuer has all required trust marks
     */
    public boolean isTrustedIssuer() {
        return identityTrustMarker && compliantActorTrustMarker && isGovernedTrustMarker();
    }

    /**
     * Evaluates if a verifier is trustworthy
     * @return true if the verifier has all required trust marks
     */
    public boolean isTrustedVerifier() {
        return identityTrustMarker && compliantActorTrustMarker && transparentVerificationTrustMarker && isGovernedTrustMarker();
    }

    /**
     * @return true if either
     */
    private boolean isGovernedTrustMarker() {
        return !governedUseCaseTrustMarker || governedUseCaseAuthorizationTrustMarker;
    }

    // Note: This class is to make lombok and maven-javadoc plugin play nicely with each other
    public static class TrustMarkersBuilder {}
}
