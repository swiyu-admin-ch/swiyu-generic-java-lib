package ch.admin.bj.swiyu.tsbuilder;

/**
 * Marker interface for Public Statement builders.
 * <p>
 * Public Statements attest that self-declared information about a subject has been recorded
 * in a public register. The self-declared content is <em>not reviewed</em>.
 * </p>
 * <p>
 * Builders in this category:
 * <ul>
 *   <li>{@link VqPsBuilder} – Verification Query Public Statement (vqPS)</li>
 * </ul>
 * </p>
 * <p>
 * Common characteristics:
 * <ul>
 *   <li>{@code sub} is <strong>required</strong> – identifies the declaring subject</li>
 *   <li>{@code jti} is <strong>required</strong> – unique identifier per statement</li>
 *   <li>{@code status} is <strong>not required</strong></li>
 * </ul>
 * </p>
 */
public interface PublicStatement {
}

