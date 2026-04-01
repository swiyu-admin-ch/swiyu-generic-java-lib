package ch.admin.bj.swiyu.tsbuilder;

/**
 * Marker interface for Trust Statement builders.
 * <p>
 * Trust Statements attest <em>verified</em> information about a subject. They are issued only
 * after formal human review and approval.
 * </p>
 * <p>
 * Builders in this category:
 * <ul>
 *   <li>{@link IdTsBuilder} – Identity Trust Statement (idTS)</li>
 *   <li>{@link PiaTsBuilder} – Protected Issuance Authorization Trust Statement (piaTS)</li>
 *   <li>{@link PvaTsBuilder} – Protected Verification Authorization Trust Statement (pvaTS)</li>
 * </ul>
 * </p>
 * <p>
 * Common characteristics:
 * <ul>
 *   <li>{@code sub} is <strong>required</strong> – identifies the verified subject</li>
 *   <li>{@code status} is <strong>required</strong></li>
 * </ul>
 * </p>
 */
public interface TrustStatement {
}

