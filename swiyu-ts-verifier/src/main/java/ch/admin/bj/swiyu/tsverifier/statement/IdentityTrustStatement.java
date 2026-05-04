package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class IdentityTrustStatement extends TrustStatement{
    /**
     * human-readable string identifying the actor in the real world
     * May include localizations
     */
    @JsonProperty("entity_name")
    private String entityName;
    /**
     *  Indicates that the subject is considered a government approved state actor
     */
    @JsonProperty("is_state_actor")
    private boolean isStateActor;
    @JsonProperty("registry_ids")
    private List<RegistryObject> registryObjects;


    @Getter
    @Setter
    @NoArgsConstructor
    private static class RegistryObject {

        /**
         * Type of the registry.
         * eg. UID for the unique enterprise identification number
         */
        private String type;
        /**
         * Identifier of the subject in the registry
         */
        private String value;
    }
}
