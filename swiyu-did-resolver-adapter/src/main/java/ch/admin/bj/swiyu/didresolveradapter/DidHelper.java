/*
 * SPDX-FileCopyrightText: 2026 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.didresolveradapter;

import lombok.experimental.UtilityClass;

import java.util.regex.Pattern;

/**
 * Utility class for validating swiyu Decentralized Identifiers (DIDs).
 * <p>
 * A syntactically valid swiyu DID uses either the {@code did:tdw} or the {@code did:webvh}
 * method, followed by a self-certifying identifier (SCID) and at least one path segment,
 * for example {@code did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch}.
 * </p>
 * <p>
 * A {@code kid} (key ID) is a DID extended by a key reference fragment
 * ({@code #assert-key-01}), for example
 * {@code did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch#assert-key-01}.
 * </p>
 * <p>
 * The helpers are stateless and thread-safe. They perform a purely syntactic check and do
 * not resolve the DID.
 * </p>
 */
@UtilityClass
public class DidHelper {

    /**
     * Pattern matching a syntactically valid swiyu DID.
     * <p>
     * The DID method must be {@code tdw} or {@code webvh}, followed by a SCID
     * ({@code Q} plus 45 base58 characters) and one or more non-empty path segments.
     * </p>
     */
    public static final Pattern DID_PATTERN =
            Pattern.compile(
                    "^did:(webvh|tdw):Q[1-9A-HJ-NP-Za-km-z]{45}(:[0-9a-zA-Z%_.-]+)++$");

    /**
     * Pattern matching a syntactically valid swiyu {@code kid}.
     * <p>
     * A {@code kid} is a {@link #DID_PATTERN valid swiyu DID} followed by a key reference
     * fragment ({@code #} plus one or more characters from {@code [0-9a-zA-Z_-]}).
     * </p>
     */
    public static final Pattern KID_PATTERN =
            Pattern.compile(
                    "^did:(webvh|tdw):Q[1-9A-HJ-NP-Za-km-z]{45}(:[0-9a-zA-Z%_.-]+)++#[0-9a-zA-Z_-]+$");

    /**
     * Checks whether the given value is a syntactically valid swiyu DID.
     *
     * @param did the DID value to check, may be {@code null}
     * @return {@code true} if {@code did} is a valid swiyu DID, {@code false} otherwise
     */
    public static boolean isValidDid(String did) {
        return did != null && !did.isBlank() && DID_PATTERN.matcher(did).matches();
    }

    /**
     * Validates that the given value is a syntactically valid swiyu DID
     * ({@code did:tdw} or {@code did:webvh} with a valid SCID and path segments).
     *
     * @param did       the DID value to validate, may be {@code null}
     * @param fieldName the field or claim name used in the error message
     * @throws IllegalArgumentException if {@code did} is {@code null}, blank or does not match
     *                                  the expected DID format
     */
    public static void validateDid(String did, String fieldName) {
        if (did == null || did.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }
        if (!DID_PATTERN.matcher(did).matches()) {
            throw new IllegalArgumentException(
                    fieldName + " must be a valid swiyu DID (did:tdw or did:webvh with SCID), got: " + did);
        }
    }

    /**
     * Checks whether the given value is a syntactically valid swiyu {@code kid}
     * (a valid swiyu DID with a key reference fragment).
     *
     * @param kid the {@code kid} value to check, may be {@code null}
     * @return {@code true} if {@code kid} is a valid swiyu {@code kid}, {@code false} otherwise
     */
    public static boolean isValidKid(String kid) {
        return kid != null && !kid.isBlank() && KID_PATTERN.matcher(kid).matches();
    }

    /**
     * Validates that the given value is a syntactically valid swiyu {@code kid}
     * (a valid swiyu DID with a key reference fragment).
     *
     * @param kid       the {@code kid} value to validate, may be {@code null}
     * @param fieldName the field or claim name used in the error message
     * @throws IllegalArgumentException if {@code kid} is {@code null}, blank or does not match
     *                                  the expected {@code kid} format
     */
    public static void validateKid(String kid, String fieldName) {
        if (kid == null || kid.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }
        if (!KID_PATTERN.matcher(kid).matches()) {
            throw new IllegalArgumentException(
                    fieldName + " must be an absolute DID (did:tdw or did:webvh) with a valid SCID and key reference fragment "
                            + "(e.g. did:tdw:QmZyt...#key-1), got: " + kid);
        }
    }
}
