package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result object returned after evaluating the trust markers of a statement.
 *
 * <p>The JSON representation contains:
 * <ul>
 *   <li><strong>trust_evaluation_id</strong> – a unique identifier for this evaluation run</li>
 *   <li><strong>evaluated_actor_did</strong> – the DID of the actor (issuer or verifier) that was
 *       evaluated</li>
 *   <li><strong>markers</strong> – the {@link TrustMarkers} instance that was used for the
 *       evaluation (may be {@code null} if the evaluation could not produce markers)</li>
 * </ul>
 *
 * <p>Fields that are {@code null} are omitted from the serialized JSON thanks to the
 * {@link JsonInclude.Include#NON_NULL} setting.
 *
 * <p>Being a {@code record}, this class automatically provides:
 * <ul>
 *   <li>a canonical constructor matching the component order,</li>
 *   <li>accessor methods {@code trustEvaluationId()}, {@code evaluatedActorDid()},
 *       and {@code markers()},</li>
 *   <li>{@code equals()}, {@code hashCode()}, and {@code toString()} implementations.</li>
 * </ul>
 *
 * @param trustEvaluationId a unique identifier for the trust evaluation instance
 * @param evaluatedActorDid the DID of the actor whose trust is being evaluated
 * @param markers the set of trust markers evaluated for the actor; may be {@code null}
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TrustVerificationResult(
    /** Identifier of the trust‑evaluation run (mapped to JSON property {@code trust_evaluation_id}). */
    @JsonProperty("trust_evaluation_id")
    String trustEvaluationId,

    /** DID of the actor that was evaluated (mapped to JSON property {@code evaluated_actor_did}). */
    @JsonProperty("evaluated_actor_did")
    String evaluatedActorDid,

    /** The {@link TrustMarkers} that were assessed for this actor (mapped to JSON property {@code markers}). */
    @JsonProperty("markers")
    TrustMarkers markers
)  {

}
