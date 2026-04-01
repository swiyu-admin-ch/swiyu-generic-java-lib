package ch.admin.bj.swiyu.tsbuilder;

/**
 * Marker interface for Trust List Statement builders.
 * <p>
 * Trust List Statements provide exhaustive and self-contained information about the swiyu
 * trust ecosystem. The <em>absence</em> of an entity from a list is semantically meaningful
 * and can be interpreted accordingly (e.g. non-compliance list).
 * </p>
 * <p>
 * Builders in this category:
 * <ul>
 *   <li>{@link NcTlsBuilder} – Non-Compliance Trust List Statement (ncTLS)</li>
 *   <li>{@link PiTlsBuilder} – Protected Issuance Trust List Statement (piTLS)</li>
 * </ul>
 * </p>
 * <p>
 * Common characteristics:
 * <ul>
 *   <li>{@code sub} is <strong>not supported</strong> – the list is not bound to a single subject</li>
 *   <li>{@code status} is <strong>required</strong></li>
 * </ul>
 * </p>
 */
public interface TrustListStatement {
}

