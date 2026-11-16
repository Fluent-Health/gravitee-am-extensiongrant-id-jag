package io.fluenthealth.gravitee.am.extensiongrant.idjag.validation;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@WireMockTest
class IdJagValidatorTest {

    static final String AUDIENCE = "https://auth.example.test/staff/oidc";
    static final String CLIENT_ID = "mcp-client";
    static final Instant NOW = Instant.parse("2026-11-16T12:00:00Z");

    String issuer;
    ECKey signingKey;
    MutableClock clock = new MutableClock(NOW);
    IdJagValidator validator;

    @BeforeEach
    void setUp(WireMockRuntimeInfo wm) throws Exception {
        issuer = wm.getHttpBaseUrl() + "/issuers/test-org";
        signingKey = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        publish(issuer, List.of(signingKey));
        validator = validator(null, null);
    }

    IdJagValidator validator(String tenant, List<String> domains) {
        return new IdJagValidator(
            new IdJagValidator.Settings(issuer, AUDIENCE, tenant, domains, 60, 300),
            new IssuerKeySource(issuer, true, clock),
            new ReplayCache(1000, clock),
            clock
        );
    }

    void publish(String iss, List<JWK> keys) {
        stubFor(
            get("/issuers/test-org/.well-known/openid-configuration").willReturn(
                okJson("{\"issuer\":\"" + iss + "\",\"jwks_uri\":\"" + issuer + "/jwks\"}")
            )
        );
        stubFor(get("/issuers/test-org/jwks").willReturn(okJson(new JWKSet(keys).toPublicJWKSet().toString())));
    }

    JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("opaque-claude-subject")
            .audience(AUDIENCE)
            .claim("client_id", CLIENT_ID)
            .claim("email", "Ada.Lovelace@Example.com")
            .issueTime(Date.from(NOW.minusSeconds(5)))
            .notBeforeTime(Date.from(NOW.minusSeconds(5)))
            .expirationTime(Date.from(NOW.plusSeconds(55)))
            .jwtID(UUID.randomUUID().toString());
    }

    String sign(JWTClaimsSet claims) throws Exception {
        return sign(claims, h -> {});
    }

    String sign(JWTClaimsSet claims, Consumer<JWSHeader.Builder> header) throws Exception {
        JWSHeader.Builder h = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(new JOSEObjectType(IdJagValidator.TYPE))
            .keyID(signingKey.getKeyID());
        header.accept(h);
        SignedJWT jwt = new SignedJWT(h.build(), claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    void assertRefused(String assertion, String messagePart) {
        assertThatThrownBy(() -> validator.validate(assertion, CLIENT_ID, Set.of()))
            .isInstanceOf(IdJagException.class)
            .hasMessageContaining(messagePart);
    }

    @Test
    void acceptsAValidAssertionAndLowerCasesTheEmail() throws Exception {
        var valid = validator.validate(sign(claims().build()), CLIENT_ID, Set.of());
        assertThat(valid.email()).isEqualTo("ada.lovelace@example.com");
        assertThat(valid.subject()).isEqualTo("opaque-claude-subject");
    }

    @Test
    void acceptsRs256() throws Exception {
        RSAKey rsa = new RSAKeyGenerator(2048).keyID("r1").generate();
        publish(issuer, List.of(signingKey, rsa));
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType(IdJagValidator.TYPE)).keyID("r1").build(),
            claims().build()
        );
        jwt.sign(new RSASSASigner(rsa));
        assertThat(validator.validate(jwt.serialize(), CLIENT_ID, Set.of()).email()).isNotBlank();
    }

    @Test
    void refusesAShortRsaKey() throws Exception {
        RSAKey rsa = new RSAKeyGenerator(1024, true).keyID("r1").generate();
        publish(issuer, List.of(rsa));
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType(IdJagValidator.TYPE)).keyID("r1").build(),
            claims().build()
        );
        jwt.sign(new RSASSASigner(rsa.toPrivateKey(), true));
        assertRefused(jwt.serialize(), "signature");
    }

    @Test
    void refusesHmacEvenWithTheRightShape() throws Exception {
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType(IdJagValidator.TYPE)).build(),
            claims().build()
        );
        jwt.sign(new MACSigner(new byte[32]));
        assertRefused(jwt.serialize(), "algorithm");
    }

    @Test
    void refusesAnUnsignedJwt() {
        assertRefused(new PlainJWT(claims().build()).serialize(), "not a signed JWT");
    }

    @Test
    void refusesTheWrongType() throws Exception {
        assertRefused(sign(claims().build(), h -> h.type(JOSEObjectType.JWT)), "typ");
        assertRefused(sign(claims().build(), h -> h.type(null)), "typ");
    }

    @Test
    void refusesAnUntrustedIssuerWithoutFetchingAnything() throws Exception {
        resetAllRequests();
        assertRefused(sign(claims().issuer("https://evil.example/issuers/x").build()), "issuer is not trusted");
        verify(0, getRequestedFor(anyUrl()));
    }

    @Test
    void refusesWhenTheDiscoveryDocumentNamesAnotherIssuer() throws Exception {
        publish("https://someone-else.example", List.of(signingKey));
        assertRefused(sign(claims().build()), "different issuer");
    }

    @Test
    void refusesASignatureByAnotherKeyEvenWithAKnownKid() throws Exception {
        ECKey other = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(IdJagValidator.TYPE)).keyID("k1").build(),
            claims().build()
        );
        jwt.sign(new ECDSASigner(other));
        assertRefused(jwt.serialize(), "signature");
    }

    @Test
    void ignoresAKeyEmbeddedInTheHeader() throws Exception {
        ECKey attacker = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(IdJagValidator.TYPE))
                .keyID("k1")
                .jwk(attacker.toPublicJWK())
                .build(),
            claims().build()
        );
        jwt.sign(new ECDSASigner(attacker));
        assertRefused(jwt.serialize(), "signature");
    }

    @Test
    void picksUpARotatedKeyAtMostOncePerInterval() throws Exception {
        validator.validate(sign(claims().build()), CLIENT_ID, Set.of());
        ECKey rotated = new ECKeyGenerator(Curve.P_256).keyID("k2").generate();
        publish(issuer, List.of(rotated));
        signingKey = rotated;
        // Inside the refetch interval an unseen kid is refused without another fetch...
        assertRefused(sign(claims().build()), "signature");
        // ...and once the interval has passed it is fetched and accepted.
        clock.set(NOW.plusSeconds(31));
        JWTClaimsSet c = claims()
            .issueTime(Date.from(NOW.plusSeconds(30)))
            .expirationTime(Date.from(NOW.plusSeconds(80)))
            .build();
        assertThat(validator.validate(sign(c), CLIENT_ID, Set.of()).email()).isNotBlank();
    }

    static final class MutableClock extends Clock {

        private volatile Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant now) {
            this.now = now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @Test
    void refusesTheWrongAudience() throws Exception {
        assertRefused(sign(claims().audience("https://other.example/oidc").build()), "audience");
        assertRefused(sign(claims().audience(List.of(AUDIENCE, "https://other.example")).build()), "audience");
        assertRefused(sign(claims().audience((String) null).build()), "audience");
    }

    @Test
    void acceptsAOneElementAudienceArray() throws Exception {
        assertThat(
            validator.validate(sign(claims().audience(List.of(AUDIENCE)).build()), CLIENT_ID, Set.of())
        ).isNotNull();
    }

    @Test
    void refusesAnotherClientsAssertion() throws Exception {
        String a = sign(claims().build());
        assertThatThrownBy(() -> validator.validate(a, "someone-else", Set.of())).hasMessageContaining("client_id");
        assertRefused(sign(claims().claim("client_id", null).build()), "client_id");
    }

    @Test
    void requiresSubAndEmail() throws Exception {
        assertRefused(sign(claims().subject(null).build()), "sub");
        assertRefused(sign(claims().claim("email", null).build()), "email");
        assertRefused(sign(claims().claim("email", "not-an-address").build()), "email");
        assertRefused(sign(claims().claim("email", "a@b@c").build()), "email");
        assertRefused(sign(claims().claim("email", List.of("a@b.c")).build()), "must be a string");
    }

    @Test
    void enforcesTime() throws Exception {
        assertRefused(
            sign(
                claims()
                    .issueTime(Date.from(NOW.minusSeconds(200)))
                    .expirationTime(Date.from(NOW.minusSeconds(61)))
                    .build()
            ),
            "expired"
        );
        assertRefused(sign(claims().issueTime(Date.from(NOW.plusSeconds(61))).build()), "future");
        assertRefused(sign(claims().notBeforeTime(Date.from(NOW.plusSeconds(61))).build()), "not yet valid");
        assertRefused(sign(claims().expirationTime(Date.from(NOW.plusSeconds(3600))).build()), "lifetime");
        assertRefused(sign(claims().expirationTime(null).build()), "exp and iat");
        assertRefused(sign(claims().issueTime(null).build()), "exp and iat");
    }

    @Test
    void allowsSkew() throws Exception {
        JWTClaimsSet c = claims()
            .issueTime(Date.from(NOW.minusSeconds(100)))
            .expirationTime(Date.from(NOW.minusSeconds(30)))
            .build();
        assertThat(validator.validate(sign(c), CLIENT_ID, Set.of())).isNotNull();
    }

    @Test
    void checksTheTenantWhenConfigured() throws Exception {
        IdJagValidator tenanted = validator("tenant-a", null);
        assertThat(
            tenanted.validate(sign(claims().claim("aud_tenant", "tenant-a").build()), CLIENT_ID, Set.of())
        ).isNotNull();
        assertThatThrownBy(() ->
            tenanted.validate(sign(claims().claim("aud_tenant", "tenant-b").build()), CLIENT_ID, Set.of())
        ).hasMessageContaining("aud_tenant");
        assertThatThrownBy(() -> tenanted.validate(sign(claims().build()), CLIENT_ID, Set.of())).hasMessageContaining(
            "aud_tenant"
        );
    }

    @Test
    void keepsTheRequestWithinTheAssertionsScope() throws Exception {
        String a = sign(claims().claim("scope", "mcp.read openid").build());
        assertThat(validator.validate(a, CLIENT_ID, Set.of("mcp.read")).scopes()).contains("mcp.read", "openid");
        String b = sign(claims().claim("scope", "mcp.read").build());
        assertThatThrownBy(() -> validator.validate(b, CLIENT_ID, Set.of("mcp.write"))).hasMessageContaining("scope");
        // No scope claim: AM's own client scope settings decide.
        assertThat(validator.validate(sign(claims().build()), CLIENT_ID, Set.of("mcp.write"))).isNotNull();
    }

    @Test
    void checksTheEmailDomainWhenConfigured() throws Exception {
        IdJagValidator restricted = validator(null, List.of("example.com"));
        assertThat(restricted.validate(sign(claims().build()), CLIENT_ID, Set.of())).isNotNull();
        assertThatThrownBy(() ->
            restricted.validate(sign(claims().claim("email", "ada@example.com.evil").build()), CLIENT_ID, Set.of())
        ).hasMessageContaining("domain");
    }

    @Test
    void acceptsAnAssertionOnlyOnce() throws Exception {
        String a = sign(claims().build());
        validator.validate(a, CLIENT_ID, Set.of());
        assertRefused(a, "already been used");
        assertRefused(sign(claims().jwtID(null).build()), "jti");
    }

    @Test
    void aRefusedAssertionDoesNotConsumeItsJti() throws Exception {
        JWTClaimsSet c = claims().build();
        String a = sign(c);
        assertThatThrownBy(() -> validator.validate(a, "someone-else", Set.of())).isInstanceOf(IdJagException.class);
        assertThat(validator.validate(a, CLIENT_ID, Set.of())).isNotNull();
    }

    @Test
    void refusesAMissingAssertion() {
        assertRefused(null, "Missing");
        assertRefused(" ", "Missing");
        assertRefused("garbage", "not a signed JWT");
    }
}
