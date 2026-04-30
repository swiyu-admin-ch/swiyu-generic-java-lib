package ch.admin.bj.swiyu.jwtvalidator;

/**
 * Unchecked exception thrown to signal failures during JWT validation.
 *
 * <p>Wraps lower-level technical exceptions ({@link java.text.ParseException},
 * {@link com.nimbusds.jose.JOSEException},
 * {@link ch.admin.eid.didresolver.DidResolveException},
 * {@link ch.admin.bj.swiyu.jwtutil.JwtUtilException}) into a single, domain-specific
 * exception that callers can handle uniformly.</p>
 */
public class JwtValidatorException extends RuntimeException {

    /**
     * Constructs a new exception with the given detail message.
     *
     * @param message human-readable description of the failure
     */
    public JwtValidatorException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the given detail message and cause.
     *
     * @param message human-readable description of the failure
     * @param cause   the underlying exception that triggered this failure
     */
    public JwtValidatorException(String message, Throwable cause) {
        super(message, cause);
    }
}
