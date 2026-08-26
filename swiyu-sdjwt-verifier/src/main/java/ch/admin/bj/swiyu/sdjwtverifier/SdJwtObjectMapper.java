package ch.admin.bj.swiyu.sdjwtverifier;

import tools.jackson.databind.ObjectMapper;

/**
 * Provides the single shared {@link ObjectMapper} instance used for all disclosure/claim
 * JSON processing within this module.
 *
 * <p>{@code ObjectMapper} is thread-safe and expensive to configure/instantiate, so per the
 * Jackson documentation it should be created once and reused rather than instantiated anew in
 * every class that needs one.</p>
 */
final class SdJwtObjectMapper {

    static final ObjectMapper INSTANCE = new ObjectMapper();

    private SdJwtObjectMapper() {
        // Utility holder - not to be instantiated
    }
}
