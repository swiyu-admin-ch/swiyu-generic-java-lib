package ch.admin.bj.swiyu.sdjwtutil;

import com.nimbusds.jose.JOSEObjectType;

import java.util.Set;


public final class SdJwtConstants {


    /**
     * Digests of Disclosures for object properties
     */
    public static final String SD_CLAIM = "_sd";
    /**
     * Hash algorithm used to generate Disclosure digests and digest over presentation
     */
    public static final String SD_ALG_CLAIM = "_sd_alg";

    /**
     * Digest of the Disclosure for an array element
     */
    public static final String SD_ARRAY_CLAIM = "...";
    /** {@code typ} value required by SD-JWT VC spec (post-migration). */
    public static final String TYP_DC_SD_JWT = "dc+sd-jwt";
    /** {@code typ} value accepted during the migration phase alongside {@link TYP_DC_SD_JWT}. */
    @Deprecated(since="OID4VCI 1.0")
    public static final String TYP_VC_SD_JWT = "vc+sd-jwt";
    
    public static final Set<String> ACCEPTED_TYP_VALUES = Set.of(SdJwtConstants.TYP_VC_SD_JWT, SdJwtConstants.TYP_DC_SD_JWT);
    /**
     * Registered JWT claims that MUST NOT appear in any Disclosure per RFC 9901 §3.2.2.2
     * and the Swiss Profile VC specification.
     */
    public static final Set<String> PROTECTED_CLAIMS = Set.of(
            "iss", 
            "nbf", 
            "exp", 
            "iat", 
            "cnf",
            "vct", 
            "vct#integrity",
            "status",
            "vct_metadata_uri", 
            "vct_metadata_uri#integrity",
            SD_CLAIM,
            SD_ALG_CLAIM,
            SD_ARRAY_CLAIM
    );
    /**
     * The compact serialized format for the SD-JWT is the concatenation of each part delineated with a single tilde ('~') character.
     */
    public static final String JWT_PART_DELINEATION_CHARACTER = "~";


    /**
     * Swiss Profile indication for verifiable credential artifacts (status list tokens, SD-JWT, ...).
     */
    public static final String VC_PROFILE_VERSION = "swiss-profile-vc:1.0.0";

    /**
     * JSON/JWT-header parameter name.
     */
    public static final String PROFILE_VERSION_PARAM = "profile_version";
    public static final JOSEObjectType KEY_BINDING_TYPE = new JOSEObjectType("kb+jwt");

    // Utility class - does not need to be instantiated
    private SdJwtConstants() {}
}
