package ch.admin.bj.swiyu.tsverifier.statement;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

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
}
