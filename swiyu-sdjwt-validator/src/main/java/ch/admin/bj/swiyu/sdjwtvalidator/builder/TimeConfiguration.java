package ch.admin.bj.swiyu.sdjwtvalidator.builder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import lombok.Builder;

@Builder
public class TimeConfiguration {
    @Builder.Default
    private Optional<Instant> expiry = Optional.empty();
    @Builder.Default    
    private Optional<Instant> notBefore = Optional.empty();
    @Builder.Default
    private Optional<Instant> issuedAt = Optional.empty();
    @Builder.Default
    private ChronoUnit roundingTime = ChronoUnit.DAYS;

    /**
     * Creates a map with the timeclaims rounded appropriately to the rounding time.
     * @return a map with JWT time claims if present. If no time claims are present an empty map is returned
     */
    public Map<String, Object> getJSONTimes() {
        Map<String, Object> times = new HashMap<>();
        expiry.ifPresent(t -> times.put("exp", roundedUp(t).getEpochSecond()));
        notBefore.ifPresent(t -> times.put("nbf", roundedDown(t).getEpochSecond()));
        issuedAt.ifPresent(t -> times.put("iat", roundedDown(t).getEpochSecond()));
        return times;
    }



    /**
     * rounds the instant up to the end minus 1 second of next roundingTime chrono unit.
     * E.g. for a day 2025-01-09 10:15:30.12345 is truncated to 2025-01-09 23:59:59
     */
    private Instant roundedUp(Instant instant) {
        return roundedDown(instant)
            .plusSeconds(roundingTime.getDuration().toSeconds())
            .minusSeconds(1);
    }

    /**
     * 
     * rounds the instant down to roundingTime chrono unit.
     * E.g. 2025-01-09 10:15:30.12345 is truncated to 2025-01-09 00:00
     */
    private Instant roundedDown(Instant instant) {
        long roundingTimeSeconds = roundingTime.getDuration().getSeconds();
        if (roundingTimeSeconds > ChronoUnit.DAYS.getDuration().getSeconds()) {
            // Round to next full rounding unit going from 1.1.1970
            return Instant.ofEpochSecond((instant.getEpochSecond() / roundingTimeSeconds) * roundingTimeSeconds);
        } else {
            return instant.truncatedTo(roundingTime);
        }
    }
}
