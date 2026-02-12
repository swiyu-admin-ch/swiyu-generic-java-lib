package ch.admin.bj.swiyu.jwtutil;

/**
 * Exception for JWT-Error.
 */
public class JwtUtilException extends RuntimeException {
    public JwtUtilException(String message) { super(message); }
    public JwtUtilException(String message, Throwable cause) { super(message, cause); }
}
