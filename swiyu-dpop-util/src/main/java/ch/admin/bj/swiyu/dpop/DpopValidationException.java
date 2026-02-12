package ch.admin.bj.swiyu.dpop;

/**
 * Exception thrown when DPoP validation fails.
 * <p>
 * Used to indicate errors in DPoP JWT structure, claims, signature, or proof-of-possession requirements.
 * </p>
 */
public class DpopValidationException extends RuntimeException {
    /**
     * Constructs a new DpopValidationException with the specified detail message.
     *
     * @param message the detail message
     */
    public DpopValidationException(String message) {
        super(message);
    }

    /**
     * Constructs a new DpopValidationException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of the exception
     */
    public DpopValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
