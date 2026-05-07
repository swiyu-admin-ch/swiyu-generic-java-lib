package ch.admin.bj.swiyu.tsverifier;

import ch.admin.bj.swiyu.jwtutil.JwtUtilException;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import ch.admin.bj.swiyu.statuslist.TokenStatusListBit;
import ch.admin.bj.swiyu.statuslist.TokenStatusList;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import ch.admin.bj.swiyu.tsverifier.statement.*;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Facade for Trust Statement Verification
 */
@Slf4j
public class TrustStatementVerifier {

    private final List<String> serializedTrustStatementJwt;
    private final List<Statement> statements;
    private final UrlRestriction urlRestriction;
    private final DidKidParser kidParser;


    /**
     * @param serializedTrustStatementJwt a list of trust statements provided about the actor
     */
    public TrustStatementVerifier(List<String> serializedTrustStatementJwt, UrlRestriction urlRestriction) {
        this.serializedTrustStatementJwt = serializedTrustStatementJwt;
        this.urlRestriction = urlRestriction;
        this.statements = parseStatements(this.serializedTrustStatementJwt);
        this.kidParser = new DidKidParser();
    }

    public TrustStatementVerifier(List<String> serializedTrustStatementJwt, UrlRestriction urlRestriction, DidKidParser kidParser) {
        this.serializedTrustStatementJwt = serializedTrustStatementJwt;
        this.statements = parseStatements(this.serializedTrustStatementJwt);
        this.urlRestriction = urlRestriction;
        this.kidParser = kidParser;
    }

    /**
     * @return the KeyIds (DID & Fragment) for which the public key is required for verification
     */
    public Set<String> getRequiredKeyIds() {
        return this.statements.stream()
                .map(Statement::getKid)
                .collect(Collectors.toSet());
    }

    public Set<String> getRequiredStatusLists() {
        return this.statements.stream()
                .filter(StatefulStatement.class::isInstance)
                .map(StatefulStatement.class::cast)
                .map(StatefulStatement::getStatusListUri)
                .collect(Collectors.toSet());
    }

    /**
     * @return {@link TrustVerificationResult} with the appropriate trust marks
     */
    public TrustVerificationResult verifyIssuanceStatements(String trustRootDid, String actorDid, String vct, JWKSet publicKeySet, List<TokenStatusListTokenDto> verifiedStatusListTokens) {
        List<Statement> validStatements = getValidStatements(trustRootDid, null, actorDid, publicKeySet, verifiedStatusListTokens);
        TrustMarkers markers = new TrustMarkGenerator(validStatements)
                .processCommonTrust(actorDid)
                .finalizeIssuerTrust(vct);
        return new TrustVerificationResult(UUID.randomUUID().toString(), actorDid, markers);
    }

    public TrustVerificationResult verifyVerifierStatements(String trustRootDid, String publicStatementIssuerDid, String actorDid, JWKSet publicKeySet, List<TokenStatusListTokenDto> verifiedStatusListTokens) {
        List<Statement> validStatements = getValidStatements(trustRootDid, publicStatementIssuerDid, actorDid, publicKeySet, verifiedStatusListTokens);
        TrustMarkers markers = new TrustMarkGenerator(validStatements)
                .processCommonTrust(actorDid)
                .finalizeVerifierTrust();
        return new TrustVerificationResult(UUID.randomUUID().toString(), actorDid, markers);
    }

    private List<Statement> getValidStatements(String trustRootDid, String publicStatementIssuerDid, String actorDid, JWKSet publicKeySet, List<TokenStatusListTokenDto> verifiedStatusListTokens) {
        return statements.stream()
                .filter(s -> hasTrustedIssuer(s, trustRootDid, publicStatementIssuerDid))
                .filter(s -> isMatchingActor(s, actorDid))
                .filter(s -> isValidStatement(s, publicKeySet))
                .filter(s -> hasValidState(s, verifiedStatusListTokens))
                .toList();
    }

    private boolean hasValidState(Statement s, List<TokenStatusListTokenDto> verifiedStatusListTokens) {
        if (s instanceof StatefulStatement statefulStatement) {
            TokenStatusListTokenDto.TokenStatusListDto tokenStatusList = findMatchingStatusList(s, verifiedStatusListTokens, statefulStatement);
            if (tokenStatusList == null) {
                return false;
            }
            try {
                TokenStatusList statusListToken = TokenStatusList.loadTokenStatusListToken(tokenStatusList.getBits(), tokenStatusList.getStatusListData());
                return statusListToken.getStatus(statefulStatement.getStatusIndex()) == TokenStatusListBit.VALID.getBitNumber();
            } catch (IOException e) {
                log.info("Status List {} cannot be loaded", statefulStatement.getStatusListUri(), e);
                throw new RuntimeException(e);
            }
        } else {
            // The statement type has no state ==> Always valid
            return true;
        }
    }

    private static TokenStatusListTokenDto.TokenStatusListDto findMatchingStatusList(Statement s, List<TokenStatusListTokenDto> verifiedStatusListTokens, StatefulStatement statefulStatement) {
        Optional<TokenStatusListTokenDto> referencedStatusList = verifiedStatusListTokens.stream()
                // Status List sub claim must match the statuslist uri in the reference
                .filter(sl -> sl.getSub().equals(statefulStatement.getStatusListUri()))
                .findAny();
        if (referencedStatusList.isEmpty()) {
            log.info("No matching token status list found for statement type {} with uri {}", s.getTyp().getType(), statefulStatement.getStatusListUri());
            return null;
        }
        return referencedStatusList.get().getStatusList();
    }


    private boolean hasTrustedIssuer(Statement s, String trustRootDid, String publicStatementIssuerDid) {
        String statementIssuer = kidParser.getDidFromAbsoluteKid(s.getKid());
        if (s.getTyp().equals(StatementType.VERIFICATION_QUERY_PUBLIC_STATEMENT)) {
            return statementIssuer.equals(publicStatementIssuerDid);
        }
        return statementIssuer.equals(trustRootDid);
    }

    private boolean isValidStatement(Statement s, JWKSet publicKeySet) {
        try {
            new DidJwtValidator(urlRestriction).validateJwt(s.getSerializedJwt(), publicKeySet);
            return true;
        } catch (JwtUtilException | JwtValidatorException e) {
            log.info("Trust Statement {} is not a valid JWT - invalid Signature or not valid", s.getTyp().getType(), e);
            return false;
        }
    }

    private boolean isMatchingActor(Statement s, String actorDid) {
        if (s instanceof TrustStatement ts) {
            return ts.getSub().equals(actorDid);
        }
        return true;
    }

    private static List<Statement> parseStatements(List<String> serializedTrustStatementsJwts) {
        StatementParser parser = new StatementParser();
        return serializedTrustStatementsJwts.stream()
                .map(parser::parse)
                .filter(Optional::isPresent)
                .map(Optional::get).toList();
    }
}
