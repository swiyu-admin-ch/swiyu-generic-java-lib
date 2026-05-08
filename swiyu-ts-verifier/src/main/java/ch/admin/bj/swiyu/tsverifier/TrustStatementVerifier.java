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
 * The {@code TrustStatementVerifier} serves as the primary entry point (Facade) for the
 * Swiss Trust Protocol 2.0 (TP 2.0) verification logic.
 * provided by an actor (Issuer or Verifier). This includes:
 * or verification queries (vqPS) and generating corresponding Trust Markers.
 * providing the necessary external dependencies (public keys and status lists) identified by this facade.
 */
@Slf4j
public class TrustStatementVerifier {

    private final List<String> serializedTrustStatementJwt;
    private final List<Statement> statements;
    private final UrlRestriction urlRestriction;
    private final DidKidParser kidParser;


    /**
     * Creates a new Trust Protocol 2.0 Statement Verifier, initialized with the statements to be verified.
     * These Statements may also be public statements in case of verifiers.
     * @param serializedTrustStatementJwt a list of trust statements provided about the actor
     * @param urlRestriction Restriction for allowed hosts where the trust statements may be hosted on
     * @param kidParser parser for DIDs
     */
    public TrustStatementVerifier(List<String> serializedTrustStatementJwt, UrlRestriction urlRestriction, DidKidParser kidParser) {
        this.serializedTrustStatementJwt = serializedTrustStatementJwt;
        this.statements = parseStatements(this.serializedTrustStatementJwt);
        this.urlRestriction = urlRestriction;
        this.kidParser = kidParser;
    }

    /**
     * Extracts all unique Key Identifiers (KIDs) from the provided statements.
     * Use this list to resolve the required public keys (DID Documents) from the network
     * before calling the verify methods.
     * @return A set of absolute DID URLs (e.g., "did:tdw:example.ch#key-1").
     */
    public Set<String> getRequiredKeyIds() {
        return this.statements.stream()
                .map(Statement::getKid)
                .collect(Collectors.toSet());
    }

    /**
     * Extracts all Status List URIs referenced by the provided statements.
     * Use this list to fetch the latest Token Status List (TSL) tokens from the Trust Registry
     * before calling the verify methods.
     * @return A set of URIs pointing to the required status list resources.
     */
    public Set<String> getRequiredStatusLists() {
        return this.statements.stream()
                .filter(StatefulStatement.class::isInstance)
                .map(StatefulStatement.class::cast)
                .map(StatefulStatement::getStatusListUri)
                .collect(Collectors.toSet());
    }

    /**
    * Performs a full trust evaluation for an Issuer.
    * not revoked, and if the Issuer is authorized to issue credentials of the given type (vct).
    * @param trustRootDid The trusted root anchor DID of the swiyu ecosystem.
    * @param actorDid The DID of the Issuer being evaluated.
    * @param vct The Verifiable Credential Type (Schema) the Issuer intends to issue.
    * @param publicKeySet The set of resolved public keys required for signature verification.
    * @param verifiedStatusListTokens The list of pre-verified Status List tokens.
    * @return A {@link TrustVerificationResult} containing the derived Trust Markers (viTM, caTM, gucTM, gucaTM).
    */
    public TrustVerificationResult verifyIssuanceStatements(String trustRootDid, String actorDid, String vct, JWKSet publicKeySet, List<TokenStatusListTokenDto> verifiedStatusListTokens) {
        List<Statement> validStatements = getValidStatements(trustRootDid, null, actorDid, publicKeySet, verifiedStatusListTokens);
        TrustMarkers markers = new TrustMarkGenerator(validStatements)
                .processCommonTrust(actorDid)
                .finalizeIssuerTrust(vct);
        return new TrustVerificationResult(UUID.randomUUID().toString(), actorDid, markers);
    }

    /**
     * Performs a full trust evaluation for a Verifier.
     * and the transparency of the specific verification query (vqPS).
     * @param trustRootDid The trusted root anchor DID of the swiyu ecosystem.
     * @param publicStatementIssuerDid The DID allowed to issue vqPS (usually the Trust Registry).
     * @param actorDid The DID of the Verifier being evaluated.
     * @param publicKeySet The set of resolved public keys required for signature verification.
     * @param verifiedStatusListTokens The list of pre-verified Status List tokens.
     * @return A {@link TrustVerificationResult} containing the derived Trust Markers (viTM, tvTM, etc.).
     */
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
