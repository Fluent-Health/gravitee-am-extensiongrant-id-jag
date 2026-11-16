package io.fluenthealth.gravitee.am.extensiongrant.idjag.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Validates an Identity Assertion JWT Authorization Grant (ID-JAG) for this authorization server.
 *
 * <p>The checks, in order, follow the ID-JAG profile used by MCP enterprise-managed authorization;
 * any failure refuses the assertion:
 *
 * <ol>
 *   <li>It is a compact JWS (an unsigned or encrypted JWT is refused).
 *   <li>{@code alg} is ES256 or RS256, and {@code typ} is {@code oauth-id-jag+jwt}.
 *   <li>{@code iss} equals the configured issuer exactly, before any key is fetched.
 *   <li>The signature verifies with a key from the issuer's discovered {@code jwks_uri}.
 *   <li>{@code aud} is exactly one value, this authorization server's issuer.
 *   <li>{@code client_id} equals the client authenticated on this token request.
 *   <li>{@code sub} and {@code email} are present.
 *   <li>{@code exp}, {@code iat} and {@code nbf} hold within the skew, and the assertion's lifetime
 *       is within the configured maximum.
 *   <li>{@code aud_tenant} matches when a tenant is configured.
 *   <li>The requested scopes are within the assertion's {@code scope}, when it carries one.
 *   <li>The email's domain is allowed, when a list is configured.
 *   <li>{@code jti} is present and has not been accepted before (checked last, so only an
 *       otherwise valid assertion consumes its jti).
 * </ol>
 */
public class IdJagValidator {

    public static final String TYPE = "oauth-id-jag+jwt";
    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.RS256);
    private static final int MIN_RSA_BITS = 2048;

    private final Settings settings;
    private final IssuerKeySource keySource;
    private final ReplayCache replayCache;
    private final Clock clock;

    /** What the validator needs from the configuration. */
    public record Settings(
        String issuer,
        String audience,
        String tenant,
        List<String> allowedEmailDomains,
        int clockSkewSeconds,
        int maxAssertionLifetimeSeconds
    ) {}

    /** A validated assertion: who it is for, and what it allows. */
    public record ValidatedAssertion(String subject, String email, String jti, Set<String> scopes) {}

    public IdJagValidator(Settings settings, IssuerKeySource keySource, ReplayCache replayCache, Clock clock) {
        this.settings = settings;
        this.keySource = keySource;
        this.replayCache = replayCache;
        this.clock = clock;
    }

    public ValidatedAssertion validate(String assertion, String requestClientId, Set<String> requestedScopes)
        throws IdJagException {
        if (assertion == null || assertion.isBlank()) {
            throw new IdJagException("Missing assertion");
        }

        // 1. A signed JWT. SignedJWT.parse refuses alg=none and JWE.
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(assertion);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new IdJagException("Assertion is not a signed JWT", e);
        }

        // 2. Header.
        JWSHeader header = jwt.getHeader();
        if (!ALLOWED_ALGORITHMS.contains(header.getAlgorithm())) {
            throw new IdJagException("Assertion algorithm is not allowed");
        }
        if (header.getType() == null || !TYPE.equalsIgnoreCase(header.getType().getType())) {
            throw new IdJagException("Assertion typ must be " + TYPE);
        }

        // 3. Issuer, before any key is fetched.
        if (!settings.issuer().equals(claims.getIssuer())) {
            throw new IdJagException("Assertion issuer is not trusted");
        }

        // 4. Signature, with keys from the issuer's own discovery document only.
        verifySignature(jwt, header);

        // 5. Audience: exactly this authorization server.
        List<String> audience = claims.getAudience();
        if (audience == null || audience.size() != 1 || !settings.audience().equals(audience.get(0))) {
            throw new IdJagException("Assertion audience is not this authorization server");
        }

        // 6. Client binding.
        String clientId = stringClaim(claims, "client_id");
        if (clientId == null || !clientId.equals(requestClientId)) {
            throw new IdJagException("Assertion client_id does not match the requesting client");
        }

        // 7. Subject and email.
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new IdJagException("Assertion has no sub");
        }
        String email = stringClaim(claims, "email");
        if (
            email == null || email.isBlank() || email.indexOf('@') <= 0 || email.indexOf('@') != email.lastIndexOf('@')
        ) {
            throw new IdJagException("Assertion has no usable email");
        }
        email = email.trim().toLowerCase(Locale.ROOT);

        // 8. Time.
        long now = clock.instant().getEpochSecond();
        long skew = settings.clockSkewSeconds();
        Date exp = claims.getExpirationTime();
        Date iat = claims.getIssueTime();
        if (exp == null || iat == null) {
            throw new IdJagException("Assertion must carry exp and iat");
        }
        long expS = exp.toInstant().getEpochSecond();
        long iatS = iat.toInstant().getEpochSecond();
        if (now > expS + skew) {
            throw new IdJagException("Assertion has expired");
        }
        if (iatS > now + skew) {
            throw new IdJagException("Assertion iat is in the future");
        }
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && nbf.toInstant().getEpochSecond() > now + skew) {
            throw new IdJagException("Assertion is not yet valid");
        }
        if (expS - iatS > settings.maxAssertionLifetimeSeconds()) {
            throw new IdJagException("Assertion lifetime is too long");
        }

        // 9. Tenant.
        if (settings.tenant() != null && !settings.tenant().isBlank()) {
            if (!settings.tenant().equals(stringClaim(claims, "aud_tenant"))) {
                throw new IdJagException("Assertion aud_tenant does not match");
            }
        }

        // 10. Scope: the request may not ask for more than the assertion grants.
        Set<String> assertionScopes = null;
        String scope = stringClaim(claims, "scope");
        if (scope != null) {
            assertionScopes = Set.copyOf(Arrays.stream(scope.trim().split("\\s+")).filter(s -> !s.isEmpty()).toList());
            if (requestedScopes != null && !assertionScopes.containsAll(requestedScopes)) {
                throw new IdJagException("Requested scope exceeds the assertion's scope");
            }
        }

        // 11. Email domain.
        List<String> domains = settings.allowedEmailDomains();
        if (domains != null && !domains.isEmpty()) {
            String domain = email.substring(email.indexOf('@') + 1);
            boolean allowed = domains.stream().anyMatch(d -> d != null && d.trim().equalsIgnoreCase(domain));
            if (!allowed) {
                throw new IdJagException("Assertion email domain is not allowed");
            }
        }

        // 12. Replay, last.
        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw new IdJagException("Assertion has no jti");
        }
        if (!replayCache.markIfNew(settings.issuer() + "\n" + jti, expS + skew)) {
            throw new IdJagException("Assertion has already been used");
        }

        return new ValidatedAssertion(subject, email, jti, assertionScopes);
    }

    private void verifySignature(SignedJWT jwt, JWSHeader header) throws IdJagException {
        List<JWK> candidates = keySource.keysFor(header.getKeyID());
        for (JWK key : candidates) {
            JWSVerifier verifier = verifierFor(key, header.getAlgorithm());
            if (verifier == null) {
                continue;
            }
            try {
                if (jwt.verify(verifier)) {
                    return;
                }
            } catch (JOSEException e) {
                // Try the next candidate.
            }
        }
        throw new IdJagException("Assertion signature is not valid");
    }

    private static JWSVerifier verifierFor(JWK key, JWSAlgorithm alg) {
        if (key.getKeyUse() != null && !KeyUse.SIGNATURE.equals(key.getKeyUse())) {
            return null;
        }
        if (key.getAlgorithm() != null && !alg.equals(key.getAlgorithm())) {
            return null;
        }
        try {
            if (JWSAlgorithm.ES256.equals(alg) && key instanceof ECKey ec && Curve.P_256.equals(ec.getCurve())) {
                return new ECDSAVerifier(ec);
            }
            if (JWSAlgorithm.RS256.equals(alg) && key instanceof RSAKey rsa && rsa.size() >= MIN_RSA_BITS) {
                return new RSASSAVerifier(rsa);
            }
        } catch (JOSEException e) {
            return null;
        }
        return null;
    }

    private static String stringClaim(JWTClaimsSet claims, String name) throws IdJagException {
        Object value = claims.getClaim(name);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String s)) {
            throw new IdJagException("Assertion claim " + name + " must be a string");
        }
        return s;
    }
}
