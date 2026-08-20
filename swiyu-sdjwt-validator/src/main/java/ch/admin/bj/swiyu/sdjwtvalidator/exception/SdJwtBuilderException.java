package ch.admin.bj.swiyu.sdjwtvalidator.exception;

/**
 * SdJwtBuilderException
 */
public class SdJwtBuilderException extends Exception {
    private static final long serialVersionUID = 1l;


    public SdJwtBuilderException(String message) {
        super(message);
    }

    public SdJwtBuilderException(Throwable cause) {
        super(cause);
    }

    public SdJwtBuilderException(String message, Throwable cause) {
        super(message, cause);
    }

}
