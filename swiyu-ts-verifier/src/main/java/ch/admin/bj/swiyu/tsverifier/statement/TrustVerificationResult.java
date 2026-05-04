package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TrustVerificationResult(
    @JsonProperty("trust_evaluation_id")
    String trustEvaluationId,
    @JsonProperty("evaluated_actor_did")
    String evaluatedActorDid,
    @JsonProperty("markers")
    TrustMarkers markers
) {

}
