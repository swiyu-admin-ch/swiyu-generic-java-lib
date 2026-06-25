package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

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
public class Statement {

    private StatementHeader statementHeaders;
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
