package ch.admin.bj.swiyu.sdjwtvalidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import lombok.extern.slf4j.Slf4j;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
/**
 * Parses the compact serialization format of an SD-JWT.
 *
 * <p>An SD-JWT has the following structure (RFC 9901 §4):
 * <pre>
 *   &lt;Issuer-signed JWT&gt;~&lt;Disclosure 1&gt;~...~&lt;Disclosure N&gt;~
 * </pre>
 * The trailing {@code ~} after the last Disclosure is mandatory.
 */
@Slf4j
public final class SdJwtParser {
    /** Utility class – not instantiable. */
    private SdJwtParser() {
    }
    private static final String SEPARATOR = "~";
    
    /**
     * Extracts the Issuer-Signed JWT (the first segment before the first {@code ~}).
     *
     * @param sdJwt the full SD-JWT string; must not be {@code null} or blank
     * @return the compact serialized Issuer-Signed JWT
     * @throws JwtValidatorException if the input is null, blank, or does not contain {@code ~}
     */
    public static String extractIssuerSignedJwt(String sdJwt) {
        requireNonBlank(sdJwt);
        int firstTildeIndex = sdJwt.indexOf(SEPARATOR);
        if (firstTildeIndex == -1) {
            throw new JwtValidatorException("Input is not a valid SD-JWT: missing '~' separator");
        }
        log.debug("Extracted Issuer-Signed JWT from SD-JWT");
        return sdJwt.substring(0, firstTildeIndex);
    }
    /**
     * Extracts all Disclosure strings from the SD-JWT.
     *
     * <p>Disclosures are the {@code ~}-separated segments between the Issuer-Signed JWT.
     * Empty segments are excluded.</p>
     *
     * @param sdJwt the full SD-JWT string; must not be {@code null} or blank
     * @return an immutable list of base64url-encoded Disclosure strings (may be empty)
     */
    public static List<String> extractDisclosures(String sdJwt) {
        requireNonBlank(sdJwt);
        String[] parts = sdJwt.split(SEPARATOR, -1);
        // parts[0] = Issuer-Signed JWT
        // parts[1..n-1] = Disclosures or empty string (trailing ~)
        return Arrays.stream(parts, 1, parts.length)
                .filter(p -> !p.isBlank())
                .filter(SdJwtParser::looksLikeDisclosure)
                .toList();
    }
    /**
     * Decodes a single base64url-encoded Disclosure into its raw JSON string.
     *
     * @param disclosure the base64url-encoded Disclosure segment
     * @return the decoded JSON string (e.g. {@code ["salt","given_name","Max"]})
     * @throws JwtValidatorException if decoding fails
     */
    public static String decodeDisclosure(String disclosure) {
        try {
            return new String(Base64.getUrlDecoder().decode(disclosure), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new JwtValidatorException(
                    "Failed to base64url-decode Disclosure: " + disclosure, e);
        }
    }
    private static void requireNonBlank(String sdJwt) {
        if (sdJwt == null || sdJwt.isBlank()) {
            throw new JwtValidatorException("SD-JWT string must not be null or blank");
        }
    }
    /**
     * A Disclosure is a plain base64url string without dots.
     * Segments containing dots are not valid Disclosures and are excluded.
     *
     * @param segment the SD-JWT part to evaluate
     * @return {@code true} if the segment looks like a Disclosure
     */
    private static boolean looksLikeDisclosure(String segment) {
        return !segment.contains(".");
    }
}
