package ch.admin.bj.swiyu.sdjwtvalidator.builder;

import java.util.Set;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Sd-JWT Vc claims with swiyu specific information
 */
@RequiredArgsConstructor
@Getter
public enum SdJwtVcClaim {
    ISSUER("iss", false, true),
    VCT("vct", true, true),
    VCT_METADATA_URI("vct_metadata_uri", false, true),
    VCT_METADATA_URI_INTEGRITY("vct_metadata_uri3integrity", false, true),
    VCT_VERSION("vct_version", false, false),
    VCT_SUBTYPE("vct_subtype", false, false),
    VCT_SUBTYPE_VERSION("vct_subtype_version", false, false),
    /**
     * note: use {@link TimeConfiguration} to set nbf claim
     */
    NOT_BEFORE("nbf", false, true),
    /**
     * note: use {@link TimeConfiguration} to set exp claim
     */
    EXPIRY("exp", false, true),
    /**
     * note: use {@link TimeConfiguration} to set iat claim
     */
    ISSUED_AT("iat", false, true);

    /**
     * Claims for time
     */
    public static final Set<SdJwtVcClaim> timeClaims = Set.of(NOT_BEFORE, EXPIRY, ISSUED_AT);

    private final String claimName;
    private final boolean required;
    private final boolean alwaysDisclosed;    

}
