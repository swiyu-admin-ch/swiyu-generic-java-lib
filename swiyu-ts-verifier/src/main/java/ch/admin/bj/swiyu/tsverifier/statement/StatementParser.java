package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.Optional;

@Slf4j
public class StatementParser {

    private final ObjectMapper mapper;

    public StatementParser() {
        this.mapper = new ObjectMapper();
    }

    public Optional<Statement> parse(String serializedJwt) {
        try {
            SignedJWT parsedStatement = SignedJWT.parse(serializedJwt);
            String jwtType = parsedStatement.getHeader().getType().toString();
            var statementType  = StatementType.getByType(jwtType);
            if (statementType.isEmpty()) {
                return Optional.empty();
            }
            var allClaims = createCombinedClaims(parsedStatement);
            Statement statement = mapper.readValue(allClaims, statementType.get().getStatementClass());
            statement.setSerializedJwt(serializedJwt);
            if (hasMissingClaim(statement)) {
                return Optional.empty();
            }
            return Optional.of(statement);
        } catch (ParseException | JsonProcessingException e) {
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

    private String createCombinedClaims(SignedJWT parsedStatement) throws ParseException, JsonProcessingException {
        var allClaims = parsedStatement.getHeader().toJSONObject();
        allClaims.putAll(parsedStatement.getJWTClaimsSet().getClaims());
        return mapper.writeValueAsString(allClaims);
    }
}
