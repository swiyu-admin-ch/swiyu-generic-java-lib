package ch.admin.bj.swiyu.sdjwtverifier;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Marker record for array elements where a disclosure was not provided.
 * Serialized JSON will have the key "_sd_not_provided" so consumers can
 * detect and validate this marker.
 */
public record DisclosureNotProvided(@JsonProperty("digest") String digest) {
}
