package ch.admin.bj.swiyu.tsbuilder;

/**
 * Domain exception thrown immediately when a builder setter or {@code build()} call detects
 * a constraint violation (missing required claim, invalid format, exceeded length limit, etc.).
 * <p>
 * This exception follows the <em>Fail-Fast</em> principle: it is thrown as early as possible –
 * inside {@code with...()} / {@code add...()} setters – so that the root cause is obvious to
 * the caller without waiting for {@code build()}.
 * </p>
 */
public class TrustStatementValidationException extends RuntimeException {

    /**
     * Creates a new {@code TrustStatementValidationException} with the given detail message.
     *
     * @param message a human-readable description of the validation failure
     */
    public TrustStatementValidationException(String message) {
        super(message);
    }
}
