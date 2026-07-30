package ch.admin.bj.swiyu.statuslist.dto;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDtoTest.SPEC_EXAMPLE_STATUS_LIST_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class TokenStatusListReferenceDtoTest {
    /**
     * Example as in spec without JWT header
     */
    protected static final String SPEC_EXAMPLE_STATUS_LIST_REFERENCE = """
            {
              "_sd": [
                "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg"
              ],
              "iss": "https://example.com/issuer",
              "iat": 1683000000,
              "exp": 1883000000,
              "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
              "status": {
                "status_list": {
                  "idx": 0,
                  "uri": "https://example.com/statuslists/1"
                }
              },
              "_sd_alg": "sha-256"
            }""";

    private static final ObjectMapper mapper = new ObjectMapper();

    @Test
    void testSpecExampleParsing() {
        var dto = assertDoesNotThrow(() -> mapper.readValue(SPEC_EXAMPLE_STATUS_LIST_REFERENCE, TokenStatusListReferenceDto.class));
        var statusListDto = dto.getStatus().getStatusList();
        assertThat(statusListDto.getIndex()).isEqualTo(0);
        assertThat(statusListDto.getUri()).isEqualTo("https://example.com/statuslists/1");
    }

    @Test
    void testMatchingReference() {
        var tokenDto = assertDoesNotThrow(() -> mapper.readValue(SPEC_EXAMPLE_STATUS_LIST_TOKEN, TokenStatusListTokenDto.class));
        var referenceDto = assertDoesNotThrow(() -> mapper.readValue(SPEC_EXAMPLE_STATUS_LIST_REFERENCE, TokenStatusListReferenceDto.class));
        assertThat(referenceDto.referencesStatusListToken(tokenDto)).isTrue();
    }
}