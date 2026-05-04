package ch.admin.bj.swiyu.tsverifier;

import ch.admin.bj.swiyu.tsverifier.statement.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

@Slf4j
class TrustMarkGenerator {

    private final TrustMarkers.TrustMarkersBuilder trustMarkersBuilder;
    private final List<Statement> validStatements;

    public TrustMarkGenerator(List<Statement> validStatements) {
        this.validStatements = validStatements;
        this.trustMarkersBuilder = TrustMarkers.builder();
    }

    public TrustMarkGenerator processCommonTrust(String actorDid) {

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

    public TrustMarkers finalizeIssuerTrust(String vct) {
        // If we have no information we must assume that the vct is governed
        trustMarkersBuilder.governedUseCaseTrustMarker(true);
        for (Statement s : validStatements) {
            if (s instanceof ProtectedIssuanceTrustListStatement piTLS) {
                trustMarkersBuilder.governedUseCaseTrustMarker(piTLS.getVctValues().contains(vct));
            }
            if (s instanceof ProtectedIssuanceAuthorizationTrustStatement piaTS) {
                trustMarkersBuilder.governedUseCaseAuthorizationTrustMarker(piaTS.getCanIssue().getVct().equals(vct));
            }
        }
        return trustMarkersBuilder.build();
    }


    public TrustMarkers finalizeVerifierTrust() {
        Set<String> authorizedFields = new HashSet<>();
        List<String> usedProtectedFields = new LinkedList<>();
        for (Statement s : validStatements) {
            if (s instanceof ProtectedVerificationAuthorizationTrustStatement pvaTS) {
                authorizedFields = new HashSet<>(pvaTS.getAuthorizedFields());
            }
            if (s instanceof VerificationQueryPublicStatement vqPS) {
                trustMarkersBuilder.transparentVerificationTrustMarker(true);
                extractUsedProtectedFields(vqPS, usedProtectedFields);
                if (!usedProtectedFields.isEmpty()) {
                    trustMarkersBuilder.governedUseCaseTrustMarker(true);
                }
            }
        }
        if (authorizedFields.containsAll(usedProtectedFields)) {
            trustMarkersBuilder.governedUseCaseAuthorizationTrustMarker(true);
        }
        return trustMarkersBuilder.build();
    }

    private static void extractUsedProtectedFields(VerificationQueryPublicStatement vqPS, List<String> usedProtectedFields) {
        try {
            final List<String> PROTECTED_CLAIMS = List.of("personal_administrative_number");
            final ObjectMapper mapper = new ObjectMapper();
            String dcqlQuery = mapper.writeValueAsString(vqPS.getRequest().getQuery());
            for (String protectedClaim : PROTECTED_CLAIMS) {
                if (dcqlQuery.contains(protectedClaim)) {
                    usedProtectedFields.add(protectedClaim);
                }
            }
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
