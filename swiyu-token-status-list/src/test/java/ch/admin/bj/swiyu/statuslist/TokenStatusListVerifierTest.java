package ch.admin.bj.swiyu.statuslist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import ch.admin.bj.swiyu.statuslist.dto.StatusVerificationResultDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListReferenceDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;

import java.util.Map;

class TokenStatusListVerifierTest {

    ObjectMapper mapper = new ObjectMapper();
    TokenStatusListVerifier verifier;
    TokenStatusListReferenceDto defaultReference;
    TokenStatusListTokenDto defaultStatusListToken;

    @BeforeEach
    void setup() throws JacksonException {
        verifier = new TokenStatusListVerifier(TokenStatusListVerifierConfig.builder().issuerMustMatch(true).build());
        defaultReference = TokenStatusListMapper.toTokenStatusListReference(
            mapper.readValue("""
            {
                "iss": "did:example:22222222",
                "status": {
                    "status_list": {
                        "idx": 1,
                        "uri": "https://www.example.com/status-lists/1"
                    }
                }
            }""", Map.class),
            new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID("did:example:123456789#key-1").build());

        defaultStatusListToken = TokenStatusListMapper.toTokenStatusListToken(
            mapper.readValue("""
            {
                "sub": "https://www.example.com/status-lists/1",
                "iat": 123456789,
                "exp": 234567891,
                "ttl": 15,
                "status_list": {
                "bits": 2,
                "lst": "eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGVIAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAAAAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9SwIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw"
                }
            }""", Map.class),
            new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID("did:example:123456789#key-2").build());

    }

    @Test
    void testVerification_whenValid() {
        StatusVerificationResultDto result = assertDoesNotThrow(() -> verifier.verifyStatus(defaultReference, defaultStatusListToken));
        assertThat(result.valid()).as("Status as index 1 should be valid and Status List Objects were valid").isTrue();
        assertThat(result.status()).as("Was valid, should be 0").hasValue(0);
    }

    @Test
    void testVerification_whenRevoked() {
        // Index 0 is revoked in the test vector
        defaultReference.getStatus().getStatusList().setIndex(0);
        StatusVerificationResultDto result = assertDoesNotThrow(() -> verifier.verifyStatus(defaultReference, defaultStatusListToken));
        assertThat(result.valid()).as("Revoked, should be not valid").isFalse();
        assertThat(result.status()).as("Should be 1 indicating revoked").hasValue(1);
    }

    @Test
    void testVerification_whenSuspended() {
        // Index 0 is revoked in the test vector
        defaultReference.getStatus().getStatusList().setIndex(1993);
        StatusVerificationResultDto result = assertDoesNotThrow(() -> verifier.verifyStatus(defaultReference, defaultStatusListToken));
        assertThat(result.valid()).as("Suspended, should be not valid").isFalse();
        assertThat(result.status()).as("Should be 2 indicating suspended").hasValue(2);
    }

    @Test
    void testVerification_whenCustomState() {
        // Index 0 is revoked in the test vector
        defaultReference.getStatus().getStatusList().setIndex(159495);
        StatusVerificationResultDto result = assertDoesNotThrow(() -> verifier.verifyStatus(defaultReference, defaultStatusListToken));
        assertThat(result.valid()).as("Not 0, should be not valid").isFalse();
        assertThat(result.status()).as("Should be 3 indicating custom state").hasValue(3);
    }

    @Test
    void testVerification_whenMismatchingSubject() {
        defaultStatusListToken.setSub("https://www.example.com/some-other-url/1");
        StatusVerificationResultDto result = assertDoesNotThrow(() -> verifier.verifyStatus(defaultReference, defaultStatusListToken));
        assertThat(result.valid()).as("Validation of status failed").isFalse();
        assertThat(result.status()).as("Status Validation was not completed").isEmpty();
    }
    @Test
    void testVerification_whenMismatchingIssuer() {
        defaultStatusListToken.setJwsHeader(new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID("did:example:incorrect#key-2").build());
        StatusVerificationResultDto result = assertDoesNotThrow(() -> verifier.verifyStatus(defaultReference, defaultStatusListToken));
        assertThat(result.valid()).as("Validation of status failed").isFalse();
        assertThat(result.status()).as("Status Validation was not completed").isEmpty();
    }


    @ParameterizedTest
    @ValueSource(strings={"statuslist+jwt", "STATUSLIST+JWT", "statuslist+JWT"})
    void testJWSHeaderValidation_whenStatusList_success(String type) {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(type)).build();
        assertThat(assertDoesNotThrow(() -> TokenStatusListVerifier.hasValidTokenStatusListTokenHeader(header)))
            .as("typ must be statuslist+jwt annd typ is not case sensitive")
            .isTrue();
    }

    @Test
    void testJWSHeaderValidation_whenOther_failed() {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();
        assertThat(assertDoesNotThrow(() -> TokenStatusListVerifier.hasValidTokenStatusListTokenHeader(header)))
            .as("typ must be statuslist+jwt")
            .isFalse();
    }
}
