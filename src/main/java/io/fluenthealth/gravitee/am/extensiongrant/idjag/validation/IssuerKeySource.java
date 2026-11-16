package io.fluenthealth.gravitee.am.extensiongrant.idjag.validation;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The trusted issuer's signing keys, found the way the ID-JAG profile requires: fetch
 * {@code <iss>/.well-known/openid-configuration}, require its {@code issuer} to equal {@code iss}
 * exactly, then read keys only from its {@code jwks_uri}. Keys or key URLs carried in an assertion's
 * header are never used.
 *
 * <p>The key set is cached for {@link #CACHE_TTL}. An unseen {@code kid} forces a refetch, at most
 * once per {@link #MIN_REFETCH_INTERVAL}, so rotation is picked up promptly while a stream of bogus
 * kids cannot turn the gateway into a request amplifier.
 */
public class IssuerKeySource {

    static final Duration CACHE_TTL = Duration.ofMinutes(15);
    static final Duration MIN_REFETCH_INTERVAL = Duration.ofSeconds(30);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(5);
    private static final int MAX_DOCUMENT_BYTES = 256 * 1024;

    private static final Logger LOGGER = LoggerFactory.getLogger(IssuerKeySource.class);

    private final String issuer;
    private final boolean allowInsecure;
    private final HttpClient http;
    private final Clock clock;

    private volatile JWKSet keys;
    private volatile long fetchedAt = 0L;

    public IssuerKeySource(String issuer, boolean allowInsecure, Clock clock) {
        this(
            issuer,
            allowInsecure,
            HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).followRedirects(HttpClient.Redirect.NEVER).build(),
            clock
        );
    }

    IssuerKeySource(String issuer, boolean allowInsecure, HttpClient http, Clock clock) {
        this.issuer = issuer;
        this.allowInsecure = allowInsecure;
        this.http = http;
        this.clock = clock;
    }

    /** The keys with this kid (or every key, when kid is null), refetching once if none match. */
    public List<JWK> keysFor(String kid) throws IdJagException {
        long now = clock.millis();
        JWKSet current = keys;
        if (current == null || now - fetchedAt > CACHE_TTL.toMillis()) {
            current = refresh(now);
        }
        List<JWK> matching = select(current, kid);
        if (matching.isEmpty() && now - fetchedAt > MIN_REFETCH_INTERVAL.toMillis()) {
            matching = select(refresh(now), kid);
        }
        return matching;
    }

    private static List<JWK> select(JWKSet set, String kid) {
        if (kid == null) {
            return set.getKeys();
        }
        return set.getKeys().stream().filter(k -> kid.equals(k.getKeyID())).toList();
    }

    private synchronized JWKSet refresh(long now) throws IdJagException {
        // Another thread may have refreshed while this one waited for the lock.
        if (keys != null && now - fetchedAt <= MIN_REFETCH_INTERVAL.toMillis()) {
            return keys;
        }
        String discoveryUrl = stripTrailingSlash(issuer) + "/.well-known/openid-configuration";
        Map<String, Object> discovery;
        try {
            discovery = JSONObjectUtils.parse(get(discoveryUrl));
        } catch (java.text.ParseException e) {
            throw new IdJagException("Issuer discovery document is not JSON", e);
        }
        Object discoveredIssuer = discovery.get("issuer");
        if (!issuer.equals(discoveredIssuer)) {
            throw new IdJagException("Issuer discovery document names a different issuer");
        }
        Object jwksUri = discovery.get("jwks_uri");
        if (!(jwksUri instanceof String jwksUrl)) {
            throw new IdJagException("Issuer discovery document has no jwks_uri");
        }
        requireAllowedScheme(jwksUrl);
        JWKSet fetched;
        try {
            fetched = JWKSet.parse(get(jwksUrl));
        } catch (java.text.ParseException e) {
            throw new IdJagException("Issuer JWKS is not a valid JWK set", e);
        }
        // Only public keys are ever used to verify.
        fetched = fetched.toPublicJWKSet();
        keys = fetched;
        fetchedAt = now;
        LOGGER.debug("Fetched {} signing key(s) for issuer {}", fetched.getKeys().size(), issuer);
        return fetched;
    }

    private String get(String url) throws IdJagException {
        requireAllowedScheme(url);
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .timeout(HTTP_TIMEOUT)
            .header("Accept", "application/json")
            .GET()
            .build();
        HttpResponse<byte[]> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IdJagException("Interrupted while fetching issuer metadata", e);
        } catch (Exception e) {
            throw new IdJagException("Could not fetch issuer metadata", e);
        }
        if (response.statusCode() != 200) {
            throw new IdJagException("Issuer metadata request returned HTTP " + response.statusCode());
        }
        byte[] body = response.body();
        if (body.length > MAX_DOCUMENT_BYTES) {
            throw new IdJagException("Issuer metadata document is too large");
        }
        return new String(body, java.nio.charset.StandardCharsets.UTF_8);
    }

    private void requireAllowedScheme(String url) throws IdJagException {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IdJagException("Issuer metadata URL is malformed", e);
        }
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if (allowInsecure && "http".equalsIgnoreCase(scheme)) {
            return;
        }
        throw new IdJagException("Issuer metadata URL must use https");
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
