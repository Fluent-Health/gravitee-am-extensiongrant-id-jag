package io.fluenthealth.gravitee.am.extensiongrant.idjag.validation;

import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers each accepted jti until its assertion can no longer be valid (exp plus skew), so the
 * same assertion is accepted at most once by this gateway instance.
 *
 * <p>The cache is per process. Behind several gateway replicas an assertion could in principle be
 * redeemed once per replica within its lifetime (under a minute for Claude-issued assertions); the
 * README states this limit. When the cache is full it refuses rather than forgets, so a flood can
 * cost availability but never opens a replay window.
 */
public class ReplayCache {

    private final ConcurrentHashMap<String, Long> seen = new ConcurrentHashMap<>();
    private final int maxEntries;
    private final Clock clock;

    public ReplayCache(int maxEntries, Clock clock) {
        this.maxEntries = maxEntries;
        this.clock = clock;
    }

    /**
     * Records {@code jti} until {@code expiresAtEpochSecond}.
     *
     * @return true if the jti was new, false if it was already seen and is still remembered.
     */
    public boolean markIfNew(String jti, long expiresAtEpochSecond) throws IdJagException {
        long now = clock.instant().getEpochSecond();
        if (seen.size() >= maxEntries) {
            purge(now);
            if (seen.size() >= maxEntries) {
                throw new IdJagException("Replay cache is full; refusing the assertion");
            }
        }
        Long previous = seen.putIfAbsent(jti, expiresAtEpochSecond);
        if (previous == null) {
            return true;
        }
        if (previous < now) {
            // The remembered entry has expired; replace it atomically.
            return seen.replace(jti, previous, expiresAtEpochSecond);
        }
        return false;
    }

    void purge(long now) {
        seen.entrySet().removeIf(e -> e.getValue() < now);
    }

    int size() {
        return seen.size();
    }
}
