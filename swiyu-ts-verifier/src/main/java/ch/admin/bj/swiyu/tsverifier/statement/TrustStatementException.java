package ch.admin.bj.swiyu.tsverifier.statement;

public class TrustStatementException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public TrustStatementException(String message) {
        super(message);
    }

    public TrustStatementException(String message, Throwable cause) {
        super(message, cause);
    }
}
