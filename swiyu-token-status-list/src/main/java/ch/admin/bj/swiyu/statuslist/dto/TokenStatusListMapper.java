package ch.admin.bj.swiyu.statuslist.dto;

import java.util.Map;

import tools.jackson.databind.ObjectMapper;

import com.nimbusds.jose.JWSHeader;
import lombok.experimental.UtilityClass;

@UtilityClass
public class TokenStatusListMapper {
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static TokenStatusListReferenceDto toTokenStatusListReference(Map<String, Object> tokenStatusListReferenceClaims, JWSHeader jwsHeader) {
        var tokenStatusListReference = OBJECT_MAPPER.convertValue(tokenStatusListReferenceClaims, TokenStatusListReferenceDto.class);
        tokenStatusListReference.setJwsHeader(jwsHeader);
        return tokenStatusListReference;
    }

    public static TokenStatusListTokenDto toTokenStatusListToken(Map<String, Object> tokenStatusListTokenClaims, JWSHeader jwsHeader) {
        var tokenStatusListToken = OBJECT_MAPPER.convertValue(tokenStatusListTokenClaims, TokenStatusListTokenDto.class);
        tokenStatusListToken.setJwsHeader(jwsHeader);
        return tokenStatusListToken;
    }
}
