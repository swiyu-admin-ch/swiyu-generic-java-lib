package ch.admin.bj.swiyu.didresolveradapter;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UrlRewriteHelperTest {
    @Test
    void rewriteUrl_withMapping_replacesPrefix() {
        String url = "https://prod.example.com/api/resource";
        Map<String, String> mapping = Map.of("https://prod.example.com", "https://test.example.com");
        String rewritten = UrlRewriteHelper.getRewrittenUrl(url, mapping);
        assertThat(rewritten).isEqualTo("https://test.example.com/api/resource");
    }

    @Test
    void rewriteUrl_noMapping_returnsOriginal() {
        String url = "https://prod.example.com/api/resource";
        Map<String, String> mapping = Map.of();
        String rewritten = UrlRewriteHelper.getRewrittenUrl(url, mapping);
        assertThat(rewritten).isEqualTo(url);
    }

    @Test
    void rewriteUrl_partialMapping_returnsOriginal() {
        String url = "https://prod.example.com/api/resource";
        Map<String, String> mapping = Map.of("https://other.com", "https://test.com");
        String rewritten = UrlRewriteHelper.getRewrittenUrl(url, mapping);
        assertThat(rewritten).isEqualTo(url);
    }

    @Test
    void rewriteUrl_nullMapping_returnsOriginal() {
        String url = "https://prod.example.com/api/resource";
        String rewritten = UrlRewriteHelper.getRewrittenUrl(url, null);
        assertThat(rewritten).isEqualTo(url);
    }

    @Test
    void rewriteUrl_replacesOnlyPrefix() {
        String url = "https://prod.example.com/api/resource?redirect=https://prod.example.com";
        Map<String, String> mapping = Map.of("https://prod.example.com", "https://test.example.com");
        String rewritten = UrlRewriteHelper.getRewrittenUrl(url, mapping);
        assertThat(rewritten).isEqualTo("https://test.example.com/api/resource?redirect=https://prod.example.com");
    }
}
