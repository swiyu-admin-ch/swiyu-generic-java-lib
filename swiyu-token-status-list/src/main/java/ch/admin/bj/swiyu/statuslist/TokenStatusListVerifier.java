package ch.admin.bj.swiyu.statuslist;

import java.io.IOException;
import java.util.Optional;

import com.nimbusds.jose.JWSHeader;

import ch.admin.bj.swiyu.statuslist.dto.StatusVerificationResultDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListReferenceDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto.TokenStatusListDto;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class TokenStatusListVerifier {
    private static final String TOKEN_STATUS_LIST_TOKEN_TYPE = "statuslist+jwt";

    private final TokenStatusListVerifierConfig config;

    /**
     * Checks whether the provided {@link JWSHeader} has the type of a token status
     * list.
     * According to Token Status List Spec
     * <a href=
     * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-5.1">
     * 5.1</a>
     * typ MUST be statuslist+jwt
     * 
     * @param tokenStatusListHeader
     * @return
     */
    public boolean hasValidTokenStatusListTokenHeader(JWSHeader tokenStatusListHeader) {
        return TOKEN_STATUS_LIST_TOKEN_TYPE.equalsIgnoreCase(tokenStatusListHeader.getType().toString());
    }

    /**
     * Verifies the revocation status of a token referenced by {@code referenceDto}
     * against the data contained in a {@link TokenStatusListTokenDto}.
     * 
     * @param referenceDto       the DTO representing the {@code status} claim of
     *                           the
     *                           token whose status is being checked
     * @param statusListTokenDto the DTO representing the Token Status List JWT
     * @return a {@link StatusVerificationResultDto} containing:
     *         <ul>
     *         <li>{@code valid} – {@code true} if the status bit equals {@code 0}
     *         (i.e., the token is valid), {@code false} otherwise</li>
     *         <li>{@code status} – the numeric status code read from the list
     *         (e.g., {@code 0}=valid, {@code 1}=revoked, {@code 2}=suspended,
     *         {@code 3..128}=application‑specific statuses).
     *          Empty if status list was not valid.</li>
     *         </ul>
     * @throws IOException if the status‑list token payload is malformed or the
     *                     bitmap cannot be decoded
     */
    public StatusVerificationResultDto verifyStatus(TokenStatusListReferenceDto referenceDto,
            TokenStatusListTokenDto statusListTokenDto) throws IOException {
        if (!isValidStateTokens(referenceDto, statusListTokenDto)) {
            return new StatusVerificationResultDto(false, Optional.empty());
        }
        TokenStatusListDto sl = statusListTokenDto.getStatusList();
        TokenStatusList statusList = TokenStatusList.loadTokenStatusListToken(sl.getBits(), sl.getStatusListData());
        int status = statusList.getStatus(referenceDto.getStatus().getStatusList().getIndex());
        return new StatusVerificationResultDto(status == 0, Optional.of(status));
    }

    private boolean isValidStateTokens(TokenStatusListReferenceDto referenceDto,
            TokenStatusListTokenDto statusListTokenDto) {
        // Validate presence of claims
        if (!referenceDto.hasRequiredClaims() || !statusListTokenDto.hasRequiredClaims()) {
            return false;
        }
        // 4.a The subject claim (sub) of the Status List Token MUST be equal to the uri
        // claim in the status_list object of the Referenced Token
        // Other checks should already be done when validating the JWT
        if (!referenceDto.referencesStatusListToken(statusListTokenDto)) {
            return false;
        }
        // Optional validation that issuer of the VC and Status List must be the same
        if (config.isIssuerMustMatch() && !matchesIssuer(referenceDto, statusListTokenDto)) {
            return false;
        }
        // All checks passed
        return true;
    }

    private boolean matchesIssuer(TokenStatusListReferenceDto referenceDto,
            TokenStatusListTokenDto statusListTokenDto) {
        return referenceDto.getIssuer() != null && statusListTokenDto.getIssuer() != null
                && referenceDto.getIssuer().equals(statusListTokenDto.getIssuer());
    }

}
