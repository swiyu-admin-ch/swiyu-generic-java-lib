package ch.admin.bj.swiyu.sdjwtbuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

class TimeConfigurationTest {
    static final Instant TIMESTAMP = Instant.parse("2025-01-09T10:15:30.12345Z");
    /**
     * Beginning of the Time bracket
     */
    static final long EXPECTED_BEGINING = 1736380800l; // 2025-01-09T00:00:00Z
    /**
     * End of Time Bracket
     */
    static final long EXPECTED_END = 1736467199l; // 2025-01-09T23:59:59Z

    @Test
    void getJSONTimes_WithAllTimesPresent_ReturnsAllRoundedTimes() {
        var config = TimeConfiguration.builder()
            .expiry(Optional.of(TIMESTAMP))
            .notBefore(Optional.of(TIMESTAMP))
            .issuedAt(Optional.of(TIMESTAMP))
            .build();

        Map<String, Object> times = config.getJSONTimes();

        assertThat(times)
            .containsEntry("exp", EXPECTED_END) 
            .containsEntry("nbf", EXPECTED_BEGINING) 
            .containsEntry("iat", EXPECTED_BEGINING);
    }

    @Test
    void getJSONTimes_WithOnlyExpiry_ReturnsOnlyExpiry() {
        var config = TimeConfiguration.builder()
            .expiry(Optional.of(TIMESTAMP))
            .build();

        Map<String, Object> times = config.getJSONTimes();

        assertThat(times)
            .containsOnlyKeys("exp")
            .containsEntry("exp", EXPECTED_END);
    }

    @Test
    void getJSONTimes_WithNoTimes_ReturnsEmptyMap() {
        var config = TimeConfiguration.builder().build();

        Map<String, Object> times = config.getJSONTimes();

        assertThat(times).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = ChronoUnit.class, mode = Mode.EXCLUDE, names = {"NANOS", "MICROS", "MILLIS", "SECONDS", "CENTURIES", "MILLENNIA", "ERAS", "FOREVER"})
    // Excluding time units which are excessively precise or long
    void getJSONTimes_WithCustomRoundingTime_RoundsAccordingToUnit(ChronoUnit unit) {
        var config = TimeConfiguration.builder()
            .expiry(Optional.of(TIMESTAMP))
            .roundingTime(unit)
            .build();

        Map<String, Object> times = config.getJSONTimes();
        Instant expiryTime = Instant.ofEpochSecond((long)times.get("exp"));
        assertThat(expiryTime).isAfter(TIMESTAMP).isBefore(TIMESTAMP.plusSeconds(unit.getDuration().toSeconds()));
    }

    @Test
    void getJSONTimes_WithNullOptionals_ReturnsEmptyMap() {
        var config = TimeConfiguration.builder()
            .expiry(Optional.empty())
            .notBefore(Optional.empty())
            .issuedAt(Optional.empty())
            .build();

        Map<String, Object> times = config.getJSONTimes();

        assertThat(times).isEmpty();
    }
}
