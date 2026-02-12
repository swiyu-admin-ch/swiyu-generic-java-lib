package ch.admin.bj.swiyu.jweutil;

/**
 * Exception für JWE-Fehler.
 */
public class JweUtilException extends RuntimeException {
    public JweUtilException(String message) { super(message); }
    public JweUtilException(String message, Throwable cause) { super(message, cause); }
}
