package ch.admin.bj.swiyu.sdjwtvalidator.exception;

public class SdJwtVerificationException extends Exception {
    private static final long serialVersionUID = 1l;

    public SdJwtVerificationException(String message) {
        super(message);
    }

    public SdJwtVerificationException(Throwable cause) {
        super(cause);
    }

    public SdJwtVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
