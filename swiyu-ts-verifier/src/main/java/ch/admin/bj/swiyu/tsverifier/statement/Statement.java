package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

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
    private Date iat;
    /**
     * Expiration time of the trust statement
     */
    private Date exp;
    /**
     * Full Serialized JWT
     */
    @JsonIgnore
    private String serializedJwt;

    public long getExp() {
        return exp.getTime();
    }

    public long getIat() {
        return iat.getTime();
    }
}
