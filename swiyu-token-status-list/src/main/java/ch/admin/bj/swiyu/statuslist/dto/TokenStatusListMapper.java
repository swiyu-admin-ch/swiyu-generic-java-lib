package ch.admin.bj.swiyu.statuslist.dto;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.experimental.UtilityClass;

@UtilityClass
public class TokenStatusListMapper {
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static TokenStatusListReferenceDto toTokenStatusListReference(Map<String, Object> tokenStatusListReferenceClaims) {
        return OBJECT_MAPPER.convertValue(tokenStatusListReferenceClaims, TokenStatusListReferenceDto.class);
    }

    public static TokenStatusListTokenDto toTokenStatusListToken(Map<String, Object> tokenStatusListTokenClaims) {
        return OBJECT_MAPPER.convertValue(tokenStatusListTokenClaims, TokenStatusListTokenDto.class);
    }
}
