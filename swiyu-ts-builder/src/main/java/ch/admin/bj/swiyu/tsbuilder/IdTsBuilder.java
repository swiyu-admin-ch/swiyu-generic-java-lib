package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builder for Identity Trust Statements (idTS).
 * <p>
 * An Identity Trust Statement asserts metadata about a legal entity registered in the Swiss
 * trust infrastructure, such as its official name, registry identifiers and actor status.
 * </p>
 *
 * <p>Required claims: {@code sub}, {@code iat}, {@code exp}, {@code status},
 * {@code entity_name}, {@code is_state_actor}, {@code registry_ids}.</p>
 *
 * <p>Fixed header {@code typ}: {@code swiyu-identity-trust-statement+jwt}</p>
 */
public class IdTsBuilder extends AbstractTrustStatementBuilder<IdTsBuilder> implements TrustStatement {

    private static final String TYP = "swiyu-identity-trust-statement+jwt";

    private final List<Map<String, String>> registryIds = new ArrayList<>();
    private boolean hasEntityName = false;
    private boolean hasIsStateActor = false;

    /**
     * Creates a new {@code IdTsBuilder} and sets the {@code typ} header to
     * {@code swiyu-identity-trust-statement+jwt}.
     */
    public IdTsBuilder() {
        setTypHeader(TYP);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected IdTsBuilder self() {
        return this;
    }

    /**
     * Adds a default (non-localized) entity name claim.
     * <p>
     * Serialized as {@code "entity_name": "<name>"} in the JWT payload.
     * </p>
     *
     * @param name the entity name, must not be {@code null} or blank
     * @return this builder for fluent chaining
     */
    public IdTsBuilder addEntityName(String name) {
        return addEntityName(null, name);
    }

    /**
     * Adds a localized entity name claim following RFC 5646 / BCP 47 locale tags.
     * <p>
     * Serialized as {@code "entity_name#<locale>": "<name>"} in the JWT payload,
     * e.g. {@code "entity_name#de-CH": "Bundesamt für Justiz"}.
     * </p>
     *
     * @param locale the BCP 47 language tag (e.g. {@code de-CH}, {@code fr}),
     *               must not be {@code null} or blank
     * @param name   the entity name in the given locale, must not be {@code null} or blank
     * @return this builder for fluent chaining
     */
    public IdTsBuilder addEntityName(String locale, String name) {
        if (name == null || name.isBlank()) {
            throw new TrustStatementValidationException("entity_name must not be null or blank");
        }
        claim(localizedKey("entity_name", locale), name);
        hasEntityName = true;
        return self();
    }

    /**
     * Sets whether the subject is a state actor within the Swiss trust infrastructure.
     *
     * @param isStateActor {@code true} if the subject is a state actor, {@code false} otherwise
     * @return this builder for fluent chaining
     */
    public IdTsBuilder withIsStateActor(Boolean isStateActor) {
        if (isStateActor == null) {
            throw new TrustStatementValidationException("is_state_actor must not be null");
        }
        claim("is_state_actor", isStateActor);
        hasIsStateActor = true;
        return self();
    }

    /**
     * Adds a registry identifier of the given type to the trust statement.
     * <p>
     * Appended to the {@code registry_ids} array as {@code {"type": "<type>", "value": "<value>"}}.
     * Multiple registry identifiers (e.g. UID, LEI) may be added by calling this method
     * repeatedly.
     * </p>
     *
     * @param type  the registry identifier type (e.g. {@code UID}), must not be {@code null}
     *              or blank
     * @param value the identifier value within the registry (e.g. {@code CHE-123.456.789}),
     *              must not be {@code null} or blank
     * @return this builder for fluent chaining
     */
    public IdTsBuilder addRegistryId(String type, String value) {
        if (type == null || type.isBlank()) {
            throw new TrustStatementValidationException("registry_id type must not be null or blank");
        }
        if (value == null || value.isBlank()) {
            throw new TrustStatementValidationException("registry_id value must not be null or blank");
        }
        Map<String, String> entry = new LinkedHashMap<>();
        entry.put("type", type);
        entry.put("value", value);
        registryIds.add(entry);
        claim("registry_ids", registryIds);
        return self();
    }

    /**
     * Validates all required claims for the Identity Trust Statement.
     * Called by {@link AbstractTrustStatementBuilder#build()} before constructing the JWT.
     *
     * @param claims the fully-built claims snapshot
     * @throws TrustStatementValidationException if any required claim is missing
     */
    @Override
    protected void validateSubclass(JWTClaimsSet claims) {
        validateRequired(claims, "sub", "sub (subject) payload claim is required");
        validateRequired(claims, "status", "status payload claim is required – call withStatus()");
        if (!hasEntityName) {
            throw new TrustStatementValidationException(
                    "at least one entity_name claim is required – call addEntityName()");
        }
        if (!hasIsStateActor) {
            throw new TrustStatementValidationException(
                    "is_state_actor claim is required – call withIsStateActor()");
        }
        if (registryIds.isEmpty()) {
            throw new TrustStatementValidationException(
                    "at least one registry_id entry is required – call addRegistryId()");
        }
    }
}
