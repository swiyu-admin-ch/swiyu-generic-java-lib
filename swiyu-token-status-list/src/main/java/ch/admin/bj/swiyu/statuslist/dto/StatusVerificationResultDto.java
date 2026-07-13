package ch.admin.bj.swiyu.statuslist.dto;

import java.util.Optional;

/**
 * DTO representing the result of a token‑status‑list verification.
 *
 * <p>The {@code status} field encodes the state of the token according to the
 * {@link ch.admin.bj.swiyu.statuslist.TokenStatusListBit} enumeration.
 * The possible values are:</p>
 * <ul>
 *   <li><strong>0</strong> – {@code VALID}: the token is valid.</li>
 *   <li><strong>1</strong> – {@code REVOKED}: the token has been revoked.</li>
 *   <li><strong>2</strong> – {@code SUSPENDED}: the token is temporarily suspended.</li>
 *   <li><strong>3 ... 256</strong> – Other Business Status Codes</li>
 * </ul>
 *
 * @param valid  {@code true} if the token is considered valid, {@code false}
 *               otherwise (e.g., revoked or suspended or unknown status).
 * @param status the numeric status code as defined above or empty if status is unknown.
 */
public record StatusVerificationResultDto(boolean valid, Optional<Integer> status) {}
