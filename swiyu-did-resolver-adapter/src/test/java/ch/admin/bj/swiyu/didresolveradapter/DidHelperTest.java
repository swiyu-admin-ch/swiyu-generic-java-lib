package ch.admin.bj.swiyu.didresolveradapter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DidHelperTest {

    private static final String VALID_TDW_DID =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch";
    private static final String VALID_WEBVH_DID =
            "did:webvh:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did";
    private static final String VALID_TDW_KID =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
    private static final String VALID_WEBVH_KID =
            "did:webvh:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:example.com#key-1";

    @ParameterizedTest
    @ValueSource(strings = {
            VALID_TDW_DID,
            VALID_WEBVH_DID,
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:example.com",
            "did:webvh:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:example.com:path%20with%20encoding"
    })
    void validateDid_validDid_doesNotThrow(String did) {
        assertThatCode(() -> DidHelper.validateDid(did, "sub")).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            VALID_TDW_DID,
            VALID_WEBVH_DID,
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:example.com"
    })
    void isValidDid_validDid_returnsTrue(String did) {
        assertThat(DidHelper.isValidDid(did)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void validateDid_nullOrBlank_throwsIllegalArgumentException(String did) {
        assertThatThrownBy(() -> DidHelper.validateDid(did, "sub"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("sub must not be null or blank");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void isValidDid_nullOrBlank_returnsFalse(String did) {
        assertThat(DidHelper.isValidDid(did)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // Unsupported DID method
            "did:key:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch",
            // No path segment after the SCID
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1",
            // SCID too short (45 characters instead of 46)
            "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pHN1f7iLTaU6p7SBms:identifier.admin.ch",
            // SCID contains a non-base58 character ('0')
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RR0A1:identifier.admin.ch",
            // SCID does not start with 'Q'
            "did:tdw:XmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch",
            // Key fragment is not part of a plain DID
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#key-01",
            // Empty path segment
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1::identifier.admin.ch",
            // Trailing path separator
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:",
            // Missing did: scheme prefix
            "tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch",
            // Scheme is case-sensitive
            "DID:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch"
    })
    void validateDid_invalidDid_throwsIllegalArgumentExceptionWithDetails(String did) {
        assertThatThrownBy(() -> DidHelper.validateDid(did, "sub"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sub must be a valid swiyu DID (did:tdw or did:webvh with SCID), got: " + did);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "did:key:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch",
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1",
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#key-01"
    })
    void isValidDid_invalidDid_returnsFalse(String did) {
        assertThat(DidHelper.isValidDid(did)).isFalse();
    }

    @Test
    void didPattern_validDid_matches() {
        assertThat(DidHelper.DID_PATTERN.matcher(VALID_TDW_DID).matches()).isTrue();
        assertThat(DidHelper.DID_PATTERN.matcher(VALID_WEBVH_DID).matches()).isTrue();
    }

    @Test
    void didPattern_invalidDid_doesNotMatch() {
        assertThat(DidHelper.DID_PATTERN.matcher("did:key:abc:def").matches()).isFalse();
    }

    // ── kid validation ────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            VALID_TDW_KID,
            VALID_WEBVH_KID,
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:example.com#key"
    })
    void validateKid_validKid_doesNotThrow(String kid) {
        assertThatCode(() -> DidHelper.validateKid(kid, "kid")).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            VALID_TDW_KID,
            VALID_WEBVH_KID,
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:example.com#key"
    })
    void isValidKid_validKid_returnsTrue(String kid) {
        assertThat(DidHelper.isValidKid(kid)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void validateKid_nullOrBlank_throwsIllegalArgumentException(String kid) {
        assertThatThrownBy(() -> DidHelper.validateKid(kid, "kid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("kid must not be null or blank");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void isValidKid_nullOrBlank_returnsFalse(String kid) {
        assertThat(DidHelper.isValidKid(kid)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // Plain DID without a key reference fragment
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch",
            // Empty key reference fragment
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#",
            // Key reference fragment contains a character outside [0-9a-zA-Z_-]
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#key.01",
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#assert key 01",
            // More than one fragment separator
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#key-1#extra",
            // Unsupported DID method
            "did:key:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#key-1",
            // SCID too short (45 characters instead of 46)
            "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pHN1f7iLTaU6p7SBms:identifier.admin.ch#key-1",
            // Fragment without a DID
            "#key-1"
    })
    void validateKid_invalidKid_throwsIllegalArgumentExceptionWithDetails(String kid) {
        assertThatThrownBy(() -> DidHelper.validateKid(kid, "kid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("kid must be an absolute DID (did:tdw or did:webvh) with a valid SCID and key "
                        + "reference fragment (e.g. did:tdw:QmZyt...#key-1), got: " + kid);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch",
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#",
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#key.01",
            "did:key:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#key-1",
            "#key-1"
    })
    void isValidKid_invalidKid_returnsFalse(String kid) {
        assertThat(DidHelper.isValidKid(kid)).isFalse();
    }

    @Test
    void kidPattern_validKid_matches() {
        assertThat(DidHelper.KID_PATTERN.matcher(VALID_TDW_KID).matches()).isTrue();
        assertThat(DidHelper.KID_PATTERN.matcher(VALID_WEBVH_KID).matches()).isTrue();
    }

    @Test
    void kidPattern_plainDidWithoutFragment_doesNotMatch() {
        assertThat(DidHelper.KID_PATTERN.matcher(VALID_TDW_DID).matches()).isFalse();
    }
}
