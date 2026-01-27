/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.didresolveradapter;

/**
 * Exception thrown to indicate a failure during Decentralized Identifier (DID) resolution.
 * <p>
 * This exception is used to signal errors encountered while resolving a DID Document or related data.
 * It may wrap lower-level exceptions or provide a custom error message for the failure.
 * </p>
 */
public class DidResolverException extends RuntimeException {
    /**
     * Constructs a new DidResolverException with the specified detail message.
     *
     * @param message the detail message
     */
    public DidResolverException(String message) {
        super(message);
    }

    /**
     * Constructs a new DidResolverException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public DidResolverException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new DidResolverException with the specified cause.
     *
     * @param cause the cause of the exception
     */
    public DidResolverException(Throwable cause) {
        super(cause);
    }
}