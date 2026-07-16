package ch.admin.bj.swiyu.tsverifier;

import ch.admin.bj.swiyu.tsverifier.statement.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Generates the {@link TrustMarkers} that are attached to a trust‑statement
 * evaluation.
 *
 * <p>The generator works in two distinct phases, always beginning with
 *
 * <ul>
 *   <li><strong>Common trust processing</strong> – {@link #processCommonTrust(String)}
 *       scans the supplied {@code validStatements} for identity‑trust and
 *       compliance‑trust information that applies to the given actor DID.
 *</ul>
 * The Second Phase is either of
 * <ul>
 *   <li><strong>Issuer‑specific trust</strong> – {@link #finalizeIssuerTrust(String)}
 *       determines the governed‑use‑case markers for an issuer based on the VCT
 *       (Verifiable Credential Type) that is being issued.
 *
 *   <li><strong>Verifier‑specific trust</strong> – {@link #finalizeVerifierTrust()}
 *       evaluates the protected‑field usage of a verification‑query and the
 *       corresponding authorisations.
 * </ul>
 *
 *
 * <p>Instances of this class are deliberately package‑private – they are meant
 * to be used only by the trust verifier implementation within the same module.
 *
 */
@Slf4j
class TrustMarkGenerator {
    
    private final TrustMarkers.TrustMarkersBuilder trustMarkersBuilder;
    private final List<Statement> validStatements;
    private static ObjectMapper mapper = new ObjectMapper();
    /**
     * Hardcoded list of Protected claims for verification. 
     * Swiss Profile 2.0 does not provide a Trust List statement for verification.
     */
    private static List<String> PROTECTED_CLAIMS = List.of("personal_administrative_number");    

    /**
     * Creates a new generator for the supplied list of already‑validated statements.
     *
     * @param validStatements a list of {@link Statement} objects that have passed
     *                        syntactic and semantic validation and can be used to
     *                        derive trust information.
     */
    TrustMarkGenerator(List<Statement> validStatements) {
        this.validStatements = validStatements;
        this.trustMarkersBuilder = TrustMarkers.builder();
    }

    /**
     * Analyses the common‑trust aspects for a specific actor DID.
     *
     * <p>Two checks are performed:
     * <ul>
     *   <li>If an {@link IdentityTrustStatement} is present, the *identity trust marker*
     *       is set to {@code true}.</li>
     *   <li>If a {@link NonComplianceTrustListStatement} is present, the method
     *       determines whether the supplied {@code actorDid} appears in the list of
     *       non‑compliant actors.  When the actor is *not* listed, the *compliant
     *       actor trust marker* is set to {@code true}; otherwise a warning is logged
     *       and the marker remains {@code false}.</li>
     * </ul>
     *
     * @param actorDid the DID of the actor (issuer or verifier) whose common trust
     *                 markers should be evaluated.
     * @return {@code this} to allow a fluent “builder‑style” usage.
     */
    TrustMarkGenerator processCommonTrust(String actorDid) {
        for (Statement statement : validStatements) {
            if (statement instanceof IdentityTrustStatement) {
                // For identity trust marker it must only be present to gain a mark
                trustMarkersBuilder.identityTrustMarker(true);
            } else if(statement instanceof NonComplianceTrustListStatement nctls) {
                var nonCompliantActor = nctls.getNonCompliantActors().stream()
                        .filter(nca -> nca.getActor().equals(actorDid))
                        .findAny();
                nonCompliantActor.ifPresentOrElse(
                        nca -> log.warn("Actor {} is non-compliant with reason {} since {}", nca.getActor(), nca.getReason(), nca.getFlaggedAt()),
                        () -> trustMarkersBuilder.compliantActorTrustMarker(true)
                );
            }
        }
        return this;
    }

    /**
     * Finalises the trust‑markers that are relevant for an *issuer*.
     *
     * <p>The method assumes that the VCT (Verifiable Credential Type) being
     * issued is governed unless a matching entry is found in a
     * {@link ProtectedIssuanceTrustListStatement}.  It also checks whether the
     * issuer holds a specific authorization for the VCT via a
     * {@link ProtectedIssuanceAuthorizationTrustStatement}.
     *
     * @param vct the VCT identifier (e.g. {@code "urn:ch.admin.fedpol.eid"}) for the
     *            credential that the issuer intends to issue.
     * @return a fully built {@link TrustMarkers} instance containing the issuer‑related
     *         markers.
     */
    TrustMarkers finalizeIssuerTrust(String vct) {
        // If we have no information we must assume that the vct is governed
        trustMarkersBuilder.governedUseCaseTrustMarker(true);
        trustMarkersBuilder.governedUseCaseAuthorizationTrustMarker(false);
        for (Statement s : validStatements) {
            if (s instanceof ProtectedIssuanceTrustListStatement piTLS) {
                trustMarkersBuilder.governedUseCaseTrustMarker(piTLS.getVctValues().contains(vct));
            }
            if (s instanceof ProtectedIssuanceAuthorizationTrustStatement piaTS && piaTS.getCanIssue().getVct().equals(vct)) {
                trustMarkersBuilder.governedUseCaseAuthorizationTrustMarker(true);
            }
        }
        return trustMarkersBuilder.build();
    }

    /**
     * Finalises the trust‑markers that are relevant for a *verifier*.
     *
     * <p>The method processes:
     * <ul>
     *   <li>{@link ProtectedVerificationAuthorizationTrustStatement} – extracts the set of
     *       fields the verifier is authorised to use.</li>
     *   <li>{@link VerificationQueryPublicStatement} – marks the verification as
     *       *transparent* and detects whether any protected claims are used in the DCQL
     *       query.  If protected claims are used, the governed‑use‑case marker is set.</li>
     * </ul>
     * Finally, if *all* protected fields that appear in the query are covered by the
     * authorisation set, the *governed‑use‑case‑authorization* marker is also set.
     *
     * @return a {@link TrustMarkers} instance containing the verifier‑related markers.
     */
    TrustMarkers finalizeVerifierTrust() {
        Set<String> authorizedFields = new HashSet<>();
        List<String> usedProtectedFields = new LinkedList<>();
        for (Statement s : validStatements) {
            if (s instanceof ProtectedVerificationAuthorizationTrustStatement pvaTS) {
                authorizedFields.addAll(pvaTS.getAuthorizedFields());
            }
            if (s instanceof VerificationQueryPublicStatement vqPS) {
                trustMarkersBuilder.transparentVerificationTrustMarker(true);
                extractUsedProtectedFields(vqPS, usedProtectedFields);
                if (!usedProtectedFields.isEmpty()) {
                    trustMarkersBuilder.governedUseCaseTrustMarker(true);
                }
            }
        }
        if (!usedProtectedFields.isEmpty() && authorizedFields.containsAll(usedProtectedFields)) {
            trustMarkersBuilder.governedUseCaseAuthorizationTrustMarker(true);
        }
        return trustMarkersBuilder.build();
    }

    private static void extractUsedProtectedFields(VerificationQueryPublicStatement vqPS, List<String> usedProtectedFields) {
        try {
            String dcqlQuery = mapper.writeValueAsString(vqPS.getRequest().getQuery());
            for (String protectedClaim : PROTECTED_CLAIMS) {
                if (dcqlQuery.contains(protectedClaim)) {
                    usedProtectedFields.add(protectedClaim);
                }
            }
        } catch (JsonProcessingException e) {
            throw new TrustStatementException("Query of Verification Query Public Statement (vqPS) cannot be parsed", e);
        }
    }
}
