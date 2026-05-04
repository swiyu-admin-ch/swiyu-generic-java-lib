package ch.admin.bj.swiyu.statuslist.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class TokenStatusListTokenDtoTest {
    /**
     * Example as in spec without JWT header
     */
    protected static final String SPEC_EXAMPLE_STATUS_LIST_TOKEN = """
            {
              "exp": 2291720170,
              "iat": 1686920170,
              "status_list": {
                "bits": 1,
                "lst": "eNrbuRgAAhcBXQ"
              },
              "sub": "https://example.com/statuslists/1",
              "ttl": 43200
            }""";

    private static final ObjectMapper mapper = new ObjectMapper();


    @Test
    void testSpecExampleParsing() {
        var dto = assertDoesNotThrow(() -> mapper.readValue(SPEC_EXAMPLE_STATUS_LIST_TOKEN, TokenStatusListTokenDto.class));
        assertThat(dto.getSub()).isEqualTo("https://example.com/statuslists/1");
        assertThat(dto.getTtl()).isEqualTo(43200);
        assertThat(dto.getStatusList().getBits()).isEqualTo(1);
        assertThat(dto.getStatusList().getStatusListData()).isEqualTo("eNrbuRgAAhcBXQ");
    }
}