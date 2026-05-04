package ch.admin.bj.swiyu.tsverifier.statement;

public class TrustStatementException extends RuntimeException {
    public TrustStatementException(String message) {
        super(message);
    }

    public TrustStatementException(String message, Throwable cause) {
        super(message, cause);
    }
}
