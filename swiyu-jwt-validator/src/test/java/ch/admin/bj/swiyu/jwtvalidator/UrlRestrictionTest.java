package ch.admin.bj.swiyu.jwtvalidator;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UrlRestrictionTest {

    private static final String ALLOWED_HOST = "identifier.admin.ch";

    private final UrlRestriction urlRestriction = new UrlRestriction(Set.of(ALLOWED_HOST));

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    @Test
    void constructor_withNullAllowedHosts_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new UrlRestriction(null));
    }

    @Test
    void constructor_withEmptyAllowedHosts_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new UrlRestriction(Set.of()));
    }

    // -------------------------------------------------------------------------
    // validateUrl – happy path
    // -------------------------------------------------------------------------

    @Test
    void validateUrl_withAllowedHost_returnsTrue() {
        assertTrue(urlRestriction.validateUrl("https://identifier.admin.ch/some/path"));
    }

    @Test
    void validateUrl_withAllowedHostUpperCase_returnsTrue() {
        // Host comparison must be case-insensitive
        assertTrue(urlRestriction.validateUrl("https://IDENTIFIER.ADMIN.CH/some/path"));
    }

    // -------------------------------------------------------------------------
    // validateUrl – rejection cases
    // -------------------------------------------------------------------------

    @Test
    void validateUrl_withUnknownHost_returnsFalse() {
        assertFalse(urlRestriction.validateUrl("https://evil.attacker.com/did-log"));
    }

    @Test
    void validateUrl_withNullUrl_returnsFalse() {
        assertFalse(urlRestriction.validateUrl(null));
    }

    @Test
    void validateUrl_withBlankUrl_returnsFalse() {
        assertFalse(urlRestriction.validateUrl("   "));
    }

    @Test
    void validateUrl_withHttpScheme_returnsFalse() {
        assertFalse(urlRestriction.validateUrl("http://identifier.admin.ch/some/path"));
    }

    @Test
    void validateUrl_withMalformedUrl_returnsFalse() {
        assertFalse(urlRestriction.validateUrl("not-a-valid-url"));
    }

    @Test
    void validateUrl_withSubdomainNotInAllowlist_returnsFalse() {
        assertFalse(urlRestriction.validateUrl("https://sub.identifier.admin.ch/path"));
    }

    // -------------------------------------------------------------------------
    // validateUrl – multiple allowed hosts
    // -------------------------------------------------------------------------

    @Test
    void validateUrl_withMultipleAllowedHosts_matchesAny() {
        UrlRestriction multi = new UrlRestriction(Set.of("identifier.admin.ch", "trust.admin.ch"));
        assertTrue(multi.validateUrl("https://trust.admin.ch/did-log"));
        assertTrue(multi.validateUrl("https://identifier.admin.ch/did-log"));
        assertFalse(multi.validateUrl("https://other.admin.ch/did-log"));
    }

}

