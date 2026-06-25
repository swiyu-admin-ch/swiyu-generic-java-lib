package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.Optional;

/**
 * Parses Statements which include 
 * <ul>
 * <li>Trust Statement</li>
 * <li>Trust List Statements</li>
 * <li>Public Statements</li>
 * </ul>
 */
@Slf4j
public class StatementParser {

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Parses a serialized JWT into a {@link Statement}.
     *
     * <p>If any parsing or deserialization exception occurs, the error is logged and an empty
     * {@link Optional} is returned.
     *
     * @param serializedJwt the compact‑serialization JWT string representing a trust statement
     * @return an {@link Optional} containing the parsed {@link Statement} when successful,
     *         or {@link Optional#empty()} if the JWT is malformed, the type is unknown,
     *         or required claims are missing
     */
    public Optional<Statement> parse(String serializedJwt) {
        try {
            SignedJWT parsedStatement = SignedJWT.parse(serializedJwt);
            String jwtType = parsedStatement.getHeader().getType().toString();
            var statementType  = StatementType.getByType(jwtType);
            if (statementType.isEmpty()) {
                return Optional.empty();
            }

            // get claims in jwt payload and map it to statement
            Statement statement = mapper.convertValue(parsedStatement.getJWTClaimsSet().getClaims(), statementType.get().getStatementClass());

            // add original jwt to statement
            statement.setSerializedJwt(serializedJwt);

            // add jwt header to statement
            StatementHeader headers = mapper.convertValue(parsedStatement.getHeader().toJSONObject(), StatementHeader.class);
            statement.setStatementHeaders(headers);

            if (hasMissingClaim(statement)) {
                return Optional.empty();
            }
            return Optional.of(statement);
        } catch (ParseException e) {
            log.info("Trust Statement {} is not parseable", serializedJwt, e);
            return Optional.empty();
        }
    }

    private boolean hasMissingClaim(Statement statement) {
        var tree = mapper.valueToTree(statement);
        return hasNullClaimRec(tree);
    }

    private boolean hasNullClaimRec(JsonNode node) {
        if (node.isNull()) {
            return true;
        }
        if (node.isContainerNode()) {
            var it = node.values();
            while(it.hasNext()) {
                if (hasNullClaimRec(it.next())) {
                    return true;
                }
            }
        }
        return false;
    }
}
