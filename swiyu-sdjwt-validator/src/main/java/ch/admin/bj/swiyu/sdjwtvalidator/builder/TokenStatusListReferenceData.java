package ch.admin.bj.swiyu.sdjwtvalidator.builder;

import java.util.Map;


/**
 * TokenStatusListReferenceData - The data without structure to create a token status list reference.
 * <pre><code>
 * {
 * "status": {
 *   "status_list": {
 *     "idx": 0,
 *     "uri": "https://example.com/statuslists/1"
 *   }
 * }
  </code></pre>
 * @param idx index to which the reference should point to
 * @param uri URI where the token status list is hosted
 */
public record TokenStatusListReferenceData(long idx, String uri) {
    public Map<String, Object> toJSONObject() {
        return Map.of("status", Map.of("status_list", Map.of("idx", idx, "uri", uri)));
    }
}
