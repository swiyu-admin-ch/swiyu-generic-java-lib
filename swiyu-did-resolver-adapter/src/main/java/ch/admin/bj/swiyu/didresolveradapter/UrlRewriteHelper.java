/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.didresolveradapter;

import lombok.experimental.UtilityClass;

import java.util.Map;

/**
 * Utility class for URL rewriting in DID resolution workflows.
 * <p>
 * Provides a static helper method to rewrite the beginning of a URL using a mapping of prefixes to replacement values.
 * This is useful for redirecting or substituting endpoints, e.g., for testing, local development, or custom routing.
 * </p>
 */
@UtilityClass
public class UrlRewriteHelper {

    /**
     * Rewrites the beginning of the given URL using the provided mapping.
     * <p>
     * If the URL starts with any key in {@code urlMappings}, that prefix is replaced with the corresponding value.
     * If no mapping matches, the original URL is returned.
     * </p>
     *
     * @param url the original URL to rewrite
     * @param urlMappings a map of URL prefixes to their replacement values
     * @return the rewritten URL if a mapping matches; otherwise, the original URL
     */
    public String getRewrittenUrl(String url, Map<String, String> urlMappings) {
        if (urlMappings == null || urlMappings.isEmpty()) {
            return url;
        }
        for (Map.Entry<String, String> entry : urlMappings.entrySet()) {
            String prefix = entry.getKey();
            if (url.startsWith(prefix)) {
                return entry.getValue() + url.substring(prefix.length());
            }
        }
        return url;
    }
}