package ch.admin.bj.swiyu.tsverifier.statement;

import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A trust protocol 2.0 statement with the fields required in the jwt format
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class Statement {
    /**
     * The specific statements define the typ string.
     */
    private StatementType typ;
    /**
     * a cryptographic identifier string defined in the swiss-profile-trust
     */
    private String alg;
    /**
     * an identifier which can be resolved to a specific cryptographic key as defined in the swiss-profile-anchor
     */
    private String kid;
    /**
     * identifying the trust protocol version to process the statement
     */
    @JsonProperty("profile_version")
    private String profileVersion;
    /**
     * Issuance time of the trust statement
     */
    private long iat;
    /**
     * Expiration time of the trust statement
     */
    private long exp;

    /**
     * Full Serialized JWT
     */
    @JsonIgnore
    private String serializedJwt;

}
