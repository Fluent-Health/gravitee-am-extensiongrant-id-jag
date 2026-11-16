package io.fluenthealth.gravitee.am.extensiongrant.idjag.validation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class ReplayCacheTest {

    static final Instant NOW = Instant.parse("2026-11-16T12:00:00Z");

    @Test
    void remembersUntilExpiry() throws Exception {
        long now = NOW.getEpochSecond();
        ReplayCache cache = new ReplayCache(10, Clock.fixed(NOW, ZoneOffset.UTC));
        assertThat(cache.markIfNew("a", now + 60)).isTrue();
        assertThat(cache.markIfNew("a", now + 60)).isFalse();

        ReplayCache later = new ReplayCache(10, Clock.fixed(NOW.plusSeconds(61), ZoneOffset.UTC));
        later.markIfNew("b", now + 60);
        // b expired before this clock's now, so it can be recorded again.
        assertThat(later.markIfNew("b", now + 120)).isTrue();
    }

    @Test
    void refusesWhenFullOfLiveEntries() throws Exception {
        long now = NOW.getEpochSecond();
        ReplayCache cache = new ReplayCache(2, Clock.fixed(NOW, ZoneOffset.UTC));
        cache.markIfNew("a", now + 60);
        cache.markIfNew("b", now + 60);
        assertThatThrownBy(() -> cache.markIfNew("c", now + 60)).hasMessageContaining("full");
    }

    @Test
    void purgesExpiredEntriesWhenFull() throws Exception {
        long now = NOW.getEpochSecond();
        ReplayCache cache = new ReplayCache(2, Clock.fixed(NOW, ZoneOffset.UTC));
        cache.markIfNew("a", now - 1);
        cache.markIfNew("b", now - 1);
        assertThat(cache.markIfNew("c", now + 60)).isTrue();
        assertThat(cache.size()).isEqualTo(1);
    }
}
