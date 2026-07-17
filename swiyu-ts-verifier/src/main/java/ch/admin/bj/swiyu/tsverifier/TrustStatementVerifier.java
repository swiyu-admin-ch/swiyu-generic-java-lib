package ch.admin.bj.swiyu.tsverifier;

import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.tsverifier.statement.*;
import lombok.extern.slf4j.Slf4j;

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

    private final List<Statement> statements;
    private final DidKidParser kidParser;


    /**
     * Creates a new Trust Protocol 2.0 Statement Verifier, initialized with the statements to be verified.
     * These Statements may also be public statements in case of verifiers.
     * @param serializedTrustStatementJwt a list of validated trust statements provided about the actor
     * @param kidParser parser for DIDs
     */
    public TrustStatementVerifier(List<String> serializedTrustStatementJwt, DidKidParser kidParser) {
        this.statements = parseStatements(serializedTrustStatementJwt);
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
                .map(s -> s.getStatementHeaders().getKid())
                .collect(Collectors.toSet());
    }

    /**
    * Performs a full trust evaluation for an Issuer.
    * not revoked, and if the Issuer is authorized to issue credentials of the given type (vct).
    * @param trustRootDid The trusted root anchor DID of the swiyu ecosystem.
    * @param actorDid The DID of the Issuer being evaluated.
    * @param vct The Verifiable Credential Type (Schema) the Issuer intends to issue.
    * @return A {@link TrustVerificationResult} containing the derived Trust Markers (viTM, caTM, gucTM, gucaTM).
    */
    public TrustVerificationResult verifyIssuanceStatements(String trustRootDid, String actorDid, String vct) {
        List<Statement> validStatements = getValidStatements(trustRootDid, null, actorDid);
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
     * @return A {@link TrustVerificationResult} containing the derived Trust Markers (viTM, tvTM, etc.).
     */
    public TrustVerificationResult verifyVerifierStatements(String trustRootDid, String publicStatementIssuerDid, String actorDid) {
        List<Statement> validStatements = getValidStatements(trustRootDid, publicStatementIssuerDid, actorDid);
        TrustMarkers markers = new TrustMarkGenerator(validStatements)
                .processCommonTrust(actorDid)
                .finalizeVerifierTrust();
        return new TrustVerificationResult(UUID.randomUUID().toString(), actorDid, markers);
    }

    private List<Statement> getValidStatements(String trustRootDid, String publicStatementIssuerDid, String actorDid) {
        return statements.stream()
                .filter(s -> hasTrustedIssuer(s, trustRootDid, publicStatementIssuerDid))
                .filter(s -> isMatchingActor(s, actorDid))
                .toList();
    }


    private boolean hasTrustedIssuer(Statement s, String trustRootDid, String publicStatementIssuerDid) {
        String statementIssuer = kidParser.getDidFromAbsoluteKid(s.getStatementHeaders().getKid());
        if (s.getStatementHeaders().getTyp().equals(StatementType.VERIFICATION_QUERY_PUBLIC_STATEMENT)) {
            return statementIssuer.equals(publicStatementIssuerDid);
        }
        return statementIssuer.equals(trustRootDid);
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
