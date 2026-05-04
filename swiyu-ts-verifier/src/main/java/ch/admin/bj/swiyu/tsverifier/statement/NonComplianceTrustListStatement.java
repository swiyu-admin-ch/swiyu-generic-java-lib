package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;


/**
 * This statement is provided by a trust registry, identified in a [swiss-profile-trust], as a means to warn
 * actors of known bad actors in the ecosystem.
 *
 */
@Getter
@Setter
@NoArgsConstructor
public class NonComplianceTrustListStatement extends TrustListStatement implements StatefulStatement {

    @JsonProperty("non_compliant_actors")
    private List<NonCompliantActor> nonCompliantActors;

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class NonCompliantActor {
        /**
         * identifier of the bad actor in a format defined in the swiss-profile-anchor
         */
        private String actor;
        /**
         * a [RFC 3339] compliant String
         */
        @JsonProperty("flagged_at")
        private String flaggedAt;
        /**
         * a human-readable String with a description of why this actor was deemed a bad actor
         */
        private String reason;
    }
}
