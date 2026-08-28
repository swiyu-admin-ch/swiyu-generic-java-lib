package ch.admin.bj.swiyu.sdjwtverifier.exception;

public class SdJwtParseException extends Exception {
    private static final long serialVersionUID = 1l;

    public SdJwtParseException(String message) {
        super(message);
    }

    public SdJwtParseException(Throwable cause) {
        super(cause);
    }

    public SdJwtParseException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
