package ch.admin.bj.swiyu.jwssignatureservice.factory.strategy;

/**
 * Exception thrown when a key management strategy fails.
 */
public class KeyStrategyException extends Exception {
    /**
     * Constructs a new KeyStrategyException with the specified message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public KeyStrategyException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new KeyStrategyException with the specified message.
     *
     * @param message the detail message
     */
    public KeyStrategyException(String message) {
        super(message);
    }
}
