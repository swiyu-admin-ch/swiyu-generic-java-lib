package ch.admin.bj.swiyu.jwtvalidator;

import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Enforces a URL allowlist (Base Registry whitelist) to prevent CSRF and "phone home" attacks.
 *
 * <p>Before any network call is made by the integrating component, the resolved DID URL must
 * be validated against the configured set of allowed hosts. Only URLs whose host exactly matches
 * one of the allowed hosts are considered trustworthy.</p>
 */
@Slf4j
public class UrlRestriction {

    private final Set<String> allowedHosts;

    /**
     * Constructs a new {@code UrlRestriction} with the given set of permitted hosts.
     *
     * @param allowedHosts the set of allowed hostname values (e.g. {@code "identifier.admin.ch"});
     *                     must not be {@code null} or empty; values are normalized to lowercase
     */
    public UrlRestriction(Set<String> allowedHosts) {
        if (allowedHosts == null || allowedHosts.isEmpty()) {
            throw new IllegalArgumentException("allowedHosts must not be null or empty");
        }
        this.allowedHosts = allowedHosts.stream()
                .map(h -> h.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Validates whether the given URL's host is contained in the configured allowlist.
     *
     * <p>The host comparison is case-insensitive to guard against trivial bypass attempts.
     * Returns {@code false} (and logs a warning) if the URL is malformed or the host is
     * not in the allowlist.</p>
     *
     * @param url the URL string to validate; must be a valid HTTPS URL
     * @return {@code true} if the host is in the allowlist, {@code false} otherwise
     */
    public boolean validateUrl(String url) {
        if (url == null || url.isBlank()) {
            log.warn("URL validation failed: URL is null or blank");
            return false;
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (!"https".equalsIgnoreCase(scheme)) {
                log.warn("URL validation failed: insecure protocol '{}' used in URL '{}'. Only HTTPS is allowed.", scheme, url);
                return false;
            }
            String host = uri.getHost();
            if (host == null) {
                log.warn("URL validation failed: could not extract host from '{}'", url);
                return false;
            }
            boolean allowed = allowedHosts.contains(host.toLowerCase(Locale.ROOT));
            if (!allowed) {
                log.warn("URL validation failed: host '{}' is not in the allowed hosts whitelist", host);
            }
            return allowed;
        } catch (URISyntaxException | IllegalArgumentException e) {
            log.warn("URL validation failed: malformed URL '{}'", url, e);
            return false;
        }
    }
}
