package ch.admin.bj.swiyu.sdjwtvalidator.builder;


import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.sdjwtvalidator.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtBuilderException;
import lombok.AccessLevel;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class SdJwtVcBuilder {

    /**
     * KID used in the created header
     */
    private final String verificationMethod;
    private final Map<String, Object> alwaysDisclosedClaims;
    private final Map<String, Object> selectiveDisclosableClaims;
    private final TimeConfiguration timeConfiguration;
    private final JWSSigner signer;


    /**
     * Creates a new builder instance for constructing a Selective Disclosure for JWT (SD-JWT) Verifiable Credential (VC).
     *
     * <p>This method initializes the builder with the provided verification method, VC claims, credential subject claims,
     * time configuration, and a signer. It validates that all required claims are present and separates the claims
     * into always-disclosed and selectively-disclosable categories.</p>
     *
     *
     * @param verificationMethod  the key identifier (KID) used in the JWT header, typically a DID URL or similar.
     *                            Must not be {@code null} or empty.
     * @param vcClaims            a map of VC-specific claims (e.g., {@code iss}, {@code sub}, {@code vct}).
     *                            Must not be {@code null}. Required claims must be present. Must not contain time claims (exp, nbf, iat)
     * @param credentialSubjectClaims a map of claims related to the credential subject (e.g., {@code given_name}, {@code family_name}).
     *                            Can be empty but must not be {@code null}.
     * @param timeConfiguration   the time-related claims (e.g., {@code iat}, {@code nbf}, {@code exp}) to be included in the JWT.
     *                            Must not be {@code null}.
     * @param signer              the {@link JWSSigner} used to sign the JWT. Must not be {@code null}.
     *
     * @return a new instance of {@link SdJwtVcBuilder} configured with the provided parameters.
     *
     * @throws SdJwtBuilderException if a required claim is missing in {@code vcClaims} or if there is an error
     *                               during the initialization of the builder.
     * @throws NullPointerException  if any of the parameters are {@code null}.
     *
     * @see SdJwtVcClaim
     * @see TimeConfiguration
     * @see JWSSigner
     */
    public static SdJwtVcBuilder createBuilder(String verificationMethod, Map<SdJwtVcClaim, Object> vcClaims, Map<String, Object> credentialSubjectClaims, TimeConfiguration timeConfiguration, JWSSigner signer) throws SdJwtBuilderException {
        Map<String, Object> alwaysDisclosedClaims = new HashMap<>();
        Map<String, Object> selectiveDisclosableClaims = new HashMap<>(credentialSubjectClaims);
        for(SdJwtVcClaim claim : SdJwtVcClaim.values()) {
            if (!vcClaims.containsKey(claim) && claim.isRequired()) {
                throw new SdJwtBuilderException(String.format("Claim %s is required", claim.getClaimName()));
            }
        }
        for (Entry<SdJwtVcClaim, Object> e : vcClaims.entrySet()) {
            if (SdJwtVcClaim.timeClaims.contains(e.getKey())) {
                throw new IllegalArgumentException(String.format("%s must not be set through vcClaims", e.getKey().getClaimName()));
            }
            if(e.getKey().isAlwaysDisclosed()) {
                alwaysDisclosedClaims.put(e.getKey().getClaimName(), e.getValue());
            } else {
                selectiveDisclosableClaims.put(e.getKey().getClaimName(), e.getValue());
            }
        }
        return new SdJwtVcBuilder(verificationMethod, alwaysDisclosedClaims, selectiveDisclosableClaims, timeConfiguration, signer);
    }

    /**
     * Creates a new SD-JWT with new random salts to allow unlinkability
     * @param statusListReference Status List Reference to be added as claim (if any)
     * @param holderPublicKey Key Binding Key to be added (if any)
     * @return
     * @throws SdJwtBuilderException
     */
    public CreatedSdJwtVc createSignedSdJwtVc(Optional<TokenStatusListReferenceData> statusListReference, Optional<JWK> holderPublicKey) throws SdJwtBuilderException {
        // Prepare Claims & Disclosures
        SDObjectBuilder sdBuilder = new SDObjectBuilder();
        putAllClaims(sdBuilder, alwaysDisclosedClaims);
        holderPublicKey.ifPresent(v -> setConfirmationKey(sdBuilder, v));
        statusListReference.ifPresent(v -> setStatusListReference(sdBuilder, v));
        List<Disclosure> disclosures = RecursiveDisclosureUtil.putSelectivelyDiscloseableData(sdBuilder, selectiveDisclosableClaims);
        
        // Create signed JWT
        try {
            JWSHeader header = JwtUtil.prepareHeaderBuilder(signer)
                .type(new JOSEObjectType(SdJwtConstants.TYP_DC_SD_JWT))
                .keyID(verificationMethod)
                .customParam(SdJwtConstants.PROFILE_VERSION_PARAM, SdJwtConstants.VC_PROFILE_VERSION)
                .build();
            JWTClaimsSet claims = JWTClaimsSet.parse(sdBuilder.build(true));
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(signer);
            return new CreatedSdJwtVc(jwt, serializedSdJwt(jwt, disclosures), jwt.getSignature().toString());
        } catch (JOSEException | ParseException e) {
            throw new SdJwtBuilderException("Failed to build JWT", e);
        }
    }

    public record CreatedSdJwtVc(SignedJWT jwt, String serializedSdJwt, String vcHash) {}


    /**
     * Create the SD-JWT in seralized compact format; 
     * <code>{serializedJwt}~{Disclosure 1}~...~{Disclosure n}~</code>
     * @param jwt
     * @param disclosures
     * @return
     */
    private String serializedSdJwt(SignedJWT jwt, List<Disclosure> disclosures) {
        return Stream.concat(
            Stream.of(jwt.serialize()), 
            Stream.concat(disclosures.stream().map(Disclosure::getDisclosure), Stream.of("")))
            .collect(Collectors.joining(SdJwtConstants.JWT_PART_DELINEATION_CHARACTER));
    }

    private void setConfirmationKey(SDObjectBuilder sdBuilder, JWK jwk) {
        sdBuilder.putClaim("cnf", Map.of("jwk", jwk.toJSONObject()));
    }

    private void setStatusListReference(SDObjectBuilder sdBuilder, TokenStatusListReferenceData statusListReference) {
        putAllClaims(sdBuilder, statusListReference.toJSONObject());
    }

    /**
     * Put all the given and time claims as always disclosed claims
     */
    private void putAllClaims(SDObjectBuilder sdBuilder, Map<String, Object> data) {
        data.entrySet().forEach(c -> sdBuilder.putClaim(c.getKey(), c.getValue()));
        timeConfiguration.getJSONTimes().entrySet().forEach(c -> sdBuilder.putClaim(c.getKey(), c.getValue()));
        
    }
}
