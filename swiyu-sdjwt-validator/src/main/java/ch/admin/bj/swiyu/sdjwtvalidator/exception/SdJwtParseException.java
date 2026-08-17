package ch.admin.bj.swiyu.sdjwtvalidator.exception;

public class SdJwtParseException extends Exception {

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
