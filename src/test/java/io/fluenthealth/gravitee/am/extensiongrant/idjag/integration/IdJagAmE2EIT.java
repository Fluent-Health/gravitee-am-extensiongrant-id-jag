package io.fluenthealth.gravitee.am.extensiongrant.idjag.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.OutputFrame;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * End-to-end check of the plugin inside a real AM 4.12.13 stack: management API, gateway and
 * MongoDB, with WireMock standing in for the assertion issuer (Claude's per-organization issuer in
 * production).
 *
 * <p>Set-up mirrors a typical staff domain: a user whose record carries an {@code externalId} and
 * a {@code app_roles} attribute, a client whose access tokens carry {@code app_roles} and
 * {@code email} as custom claims, and an MCP_SERVER protected resource. The test then proves, at the
 * token endpoint, that a valid ID-JAG is exchanged for a token whose {@code sub} and claims are the
 * ones a normal sign-in gives the same user, and that each refusal case comes back as
 * {@code invalid_grant} without creating or altering users.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class IdJagAmE2EIT {

    private static final Logger logger = LoggerFactory.getLogger(IdJagAmE2EIT.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Network network = Network.newNetwork();
    private static final String MONGO_OPTS = "serverSelectionTimeoutMS=5000&connectTimeoutMS=5000&socketTimeoutMS=5000";
    private static final String AM_MONGO_URI = "mongodb://mongodb-am:27017/gravitee?" + MONGO_OPTS;
    private static final String AM_VERSION = System.getProperty("am.version", "4.12.13");
    private static final String MGMT = "/management/organizations/DEFAULT/environments/DEFAULT";

    // As the AM gateway reaches it, inside the Docker network.
    private static final String ISSUER = "http://issuer:8080/issuers/test-org";
    private static final String CLIENT_ID = "mcp-client";
    private static final String CLIENT_SECRET = "client-secret-for-tests";
    private static final String PASSWORD_CLIENT_ID = "password-client";
    private static final String MCP_RESOURCE = "https://api.example.test/mcp";
    private static final String USER_EMAIL = "Ada.Lovelace@Example.test";
    private static final String USER_PASSWORD = "S3cure-Passw0rd!x";
    private static final String DISABLED_EMAIL = "gone@example.test";

    private static final MongoDBContainer mongo = new MongoDBContainer("mongo:7.0")
        .withNetwork(network)
        .withNetworkAliases("mongodb-am");

    private static final GenericContainer<?> issuer = new GenericContainer<>("wiremock/wiremock:3.5.4")
        .withNetwork(network)
        .withNetworkAliases("issuer")
        .withExposedPorts(8080)
        .waitingFor(Wait.forHttp("/__admin").forStatusCode(200));

    private static final GenericContainer<?> amManagement = amContainer("am-management-api", "am-management", 8093);
    private static final GenericContainer<?> amGateway = amContainer("am-gateway", "am-gateway", 8092)
        .withEnv("gravitee_services_sync_delay", "1000")
        .withEnv("gravitee_services_sync_unit", "MILLISECONDS");

    private static final HttpClient http = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    private static ECKey signingKey;
    private static String mgmtBase;
    private static String gatewayBase;
    private static String adminToken;
    private static String domainId;
    private static String domainPath;
    private static String audience;
    private static String userSource;
    private static String userId;
    private static String userExternalId;
    private static long usersBefore;

    private static GenericContainer<?> amContainer(String image, String alias, int port) {
        int corePort = port + 10000;
        return new GenericContainer<>("graviteeio/" + image + ":" + AM_VERSION)
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
            .withNetwork(network)
            .withNetworkAliases(alias)
            .withExposedPorts(port, corePort)
            .withEnv("gravitee_ds_mongodb_host", "mongodb-am")
            .withEnv("gravitee_ds_mongodb_port", "27017")
            .withEnv("gravitee_ds_mongodb_dbname", "gravitee")
            .withEnv("gravitee_management_type", "mongodb")
            .withEnv("gravitee_management_mongodb_uri", AM_MONGO_URI)
            .withEnv("gravitee_oauth2_type", "mongodb")
            .withEnv("gravitee_oauth2_mongodb_uri", AM_MONGO_URI)
            .withEnv("gravitee_services_core_http_enabled", "true")
            .withEnv("gravitee_services_core_http_port", String.valueOf(corePort))
            .withEnv("gravitee_services_core_http_host", "0.0.0.0")
            .withEnv("gravitee_services_core_http_authentication_type", "none")
            .withLogConsumer(logs(alias))
            .waitingFor(
                Wait.forHttp("/_node/health")
                    .forPort(corePort)
                    .forStatusCode(200)
                    .withStartupTimeout(Duration.ofSeconds(300))
            );
    }

    @BeforeAll
    static void setUp() throws Exception {
        Path zip;
        try (Stream<Path> files = Files.list(Paths.get("target"))) {
            zip = files
                .filter(p -> p.getFileName().toString().matches("gravitee-am-extensiongrant-id-jag-.*\\.zip"))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Plugin zip not in target/: run mvn package first"));
        }
        logger.info("Mounting plugin {} into AM {}", zip.getFileName(), AM_VERSION);
        amManagement.withCopyFileToContainer(
            MountableFile.forHostPath(zip),
            "/opt/graviteeio-am-management-api/plugins/" + zip.getFileName()
        );
        amGateway.withCopyFileToContainer(
            MountableFile.forHostPath(zip),
            "/opt/graviteeio-am-gateway/plugins/" + zip.getFileName()
        );

        mongo.start();
        issuer.start();
        amManagement.dependsOn(mongo).start();
        amGateway.dependsOn(mongo, amManagement).start();
        mgmtBase = "http://" + amManagement.getHost() + ":" + amManagement.getMappedPort(8093);
        gatewayBase = "http://" + amGateway.getHost() + ":" + amGateway.getMappedPort(8092);

        signingKey = new ECKeyGenerator(Curve.P_256).keyID("claude-1").generate();
        publishIssuer(ISSUER, signingKey);

        adminToken = adminLogin();
        bootstrapDomain();
    }

    @AfterAll
    static void tearDown() {
        Stream.of(amGateway, amManagement, issuer, mongo).filter(Objects::nonNull).forEach(GenericContainer::stop);
        network.close();
    }

    // ---------------------------------------------------------------- tests

    @Test
    @Order(1)
    void pluginIsInstalledInBothNodes() throws Exception {
        JsonNode plugins = json(mgmt("GET", "/management/platform/plugins/extensionGrants", null), 200);
        assertThat(plugins.findValuesAsText("id")).contains("id-jag-am-extension-grant");
    }

    @Test
    @Order(2)
    void exchangesAValidAssertionForTheSameTokenANormalSignInGives() throws Exception {
        HttpResponse<String> res = token(assertion(c -> {}), Map.of("scope", "openid mcp.read"));
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        JsonNode body = MAPPER.readTree(res.body());
        JsonNode claims = payload(body.path("access_token").asText());
        logger.info("ID-JAG access token claims: {}", claims);

        assertThat(claims.path("email").asText()).isEqualTo(USER_EMAIL);
        assertThat(claims.path("app_roles").toString()).contains("reader");
        assertThat(claims.path("client_id").asText()).isEqualTo(CLIENT_ID);

        // The same person signing in normally (password grant through the user's own IdP).
        HttpResponse<String> pw = form(
            "/" + domainPath + "/oauth/token",
            Map.of(
                "grant_type",
                "password",
                "username",
                USER_EMAIL.toLowerCase(),
                "password",
                USER_PASSWORD,
                "client_id",
                PASSWORD_CLIENT_ID,
                "client_secret",
                CLIENT_SECRET,
                "scope",
                "openid"
            )
        );
        assertThat(pw.statusCode()).as(pw.body()).isEqualTo(200);
        JsonNode pwClaims = payload(MAPPER.readTree(pw.body()).path("access_token").asText());
        assertThat(claims.path("sub").asText())
            .as("sub matches a normal sign-in")
            .isEqualTo(pwClaims.path("sub").asText());

        // The stored record is untouched apart from login bookkeeping.
        JsonNode user = json(mgmt("GET", MGMT + "/domains/" + domainId + "/users/" + userId, null), 200);
        assertThat(user.path("externalId").asText()).isEqualTo(userExternalId);
        assertThat(user.path("additionalInformation").path("app_roles").toString()).contains("reader");
        assertThat(user.path("source").asText()).isNotBlank();
    }

    @Test
    @Order(3)
    void bindsTheTokenToTheRequestedResource() throws Exception {
        HttpResponse<String> res = token(assertion(c -> {}), Map.of("resource", MCP_RESOURCE));
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        JsonNode claims = payload(MAPPER.readTree(res.body()).path("access_token").asText());
        assertThat(claims.path("aud").toString()).contains(MCP_RESOURCE);
    }

    @Test
    @Order(4)
    void refusesAReplayedAssertion() throws Exception {
        String a = assertion(c -> {});
        assertThat(token(a, Map.of()).statusCode()).isEqualTo(200);
        assertInvalidGrant(token(a, Map.of()), "already been used");
    }

    @Test
    @Order(5)
    void refusesEachBrokenAssertion() throws Exception {
        assertInvalidGrant(token(assertion(c -> c.audience("https://elsewhere.example/oidc")), Map.of()), "audience");
        assertInvalidGrant(token(assertion(c -> c.claim("client_id", "other-client")), Map.of()), "client_id");
        assertInvalidGrant(token(assertion(c -> c.issuer("http://issuer:8080/issuers/other")), Map.of()), "issuer");
        assertInvalidGrant(
            token(assertion(c -> c.expirationTime(Date.from(Instant.now().minusSeconds(120)))), Map.of()),
            "expired"
        );
        ECKey stranger = new ECKeyGenerator(Curve.P_256).keyID("claude-1").generate();
        assertInvalidGrant(token(sign(claims(c -> {}).build(), stranger), Map.of()), "signature");
        assertInvalidGrant(token("not-a-jwt", Map.of()), "not a signed JWT");
    }

    @Test
    @Order(6)
    void refusesUnknownAndDisabledUsersWithoutCreatingAnyone() throws Exception {
        assertInvalidGrant(token(assertion(c -> c.claim("email", "nobody@example.test")), Map.of()), "No user");
        assertInvalidGrant(token(assertion(c -> c.claim("email", DISABLED_EMAIL)), Map.of()), "disabled");
        assertThat(countUsers()).as("no user was created").isEqualTo(usersBefore);
    }

    @Test
    @Order(7)
    void aClientWithoutTheGrantCannotUseIt() throws Exception {
        HttpResponse<String> res = form(
            "/" + domainPath + "/oauth/token",
            Map.of(
                "grant_type",
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion",
                assertion(c -> c.claim("client_id", PASSWORD_CLIENT_ID)),
                "client_id",
                PASSWORD_CLIENT_ID,
                "client_secret",
                CLIENT_SECRET
            )
        );
        assertThat(res.statusCode()).as(res.body()).isIn(400, 401);
        assertThat(res.body()).containsAnyOf("unauthorized_client", "unsupported_grant_type", "invalid_grant");
    }

    // ------------------------------------------------------------ bootstrap

    private static void bootstrapDomain() throws Exception {
        JsonNode domain = json(
            mgmt(
                "POST",
                MGMT + "/domains",
                Map.of("name", "staff", "description", "ID-JAG E2E", "dataPlaneId", "default")
            ),
            201
        );
        domainId = domain.path("id").asText();
        domainPath = domain.path("path").asText().replaceFirst("^/", "");
        logger.info("Domain {} at /{}", domainId, domainPath);
        json(mgmt("PATCH", MGMT + "/domains/" + domainId, Map.of("enabled", true)), 200);

        // The domain's default identity provider is where its users live here; in production it
        // is the corporate SSO provider.
        JsonNode idps = json(mgmt("GET", MGMT + "/domains/" + domainId + "/identities", null), 200);
        userSource = idps.get(0).path("id").asText();
        logger.info("User source (identity provider) {}", userSource);

        createScope("mcp.read");

        JsonNode user = createUser(USER_EMAIL, "Ada", "Lovelace", true);
        userId = user.path("id").asText();
        userExternalId = user.path("externalId").asText();
        assertThat(userExternalId).as("seeded user has an externalId").isNotBlank();
        createUser(DISABLED_EMAIL, "Gone", "Away", false);

        json(
            mgmt(
                "POST",
                MGMT + "/domains/" + domainId + "/protected-resources",
                Map.of("name", "mcp-server", "type", "MCP_SERVER", "resourceIdentifiers", List.of(MCP_RESOURCE))
            ),
            201
        );

        waitForGateway();
        JsonNode discovery = json(get(gatewayBase + "/" + domainPath + "/oidc/.well-known/openid-configuration"), 200);
        audience = discovery.path("issuer").asText();
        assertThat(discovery.path("grant_types_supported").toString()).contains(
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );
        logger.info("Audience (domain issuer) {}", audience);

        Map<String, Object> config = new LinkedHashMap<>();
        config.put("grantType", "urn:ietf:params:oauth:grant-type:jwt-bearer");
        config.put("issuer", ISSUER);
        config.put("audience", audience);
        config.put("domainId", domainId);
        config.put("dataPlaneId", "default");
        config.put("userSource", userSource);
        config.put("allowInsecureIssuer", true);
        JsonNode grant = json(
            mgmt(
                "POST",
                MGMT + "/domains/" + domainId + "/extensionGrants",
                Map.of(
                    "type",
                    "id-jag-am-extension-grant",
                    "name",
                    "Claude-issued ID-JAG",
                    "grantType",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "identityProvider",
                    userSource,
                    "createUser",
                    true,
                    "userExists",
                    false,
                    "configuration",
                    MAPPER.writeValueAsString(config)
                )
            ),
            201
        );
        String grantId = grant.path("id").asText();

        List<Map<String, Object>> claims = List.of(
            Map.of(
                "tokenType",
                "access_token",
                "claimName",
                "app_roles",
                "claimValue",
                "{#context.attributes['user'].additionalInformation['app_roles']}"
            ),
            Map.of(
                "tokenType",
                "access_token",
                "claimName",
                "email",
                "claimValue",
                "{#context.attributes['user'].email}"
            )
        );
        createClient(CLIENT_ID, List.of("urn:ietf:params:oauth:grant-type:jwt-bearer~" + grantId), claims, List.of());
        createClient(PASSWORD_CLIENT_ID, List.of("password"), claims, List.of(userSource));

        usersBefore = countUsers();
        // Let the gateway pick up the grant and the clients.
        waitForToken();
    }

    private static void createScope(String key) throws Exception {
        json(
            mgmt(
                "POST",
                MGMT + "/domains/" + domainId + "/scopes",
                Map.of("key", key, "name", key, "description", key, "discovery", true)
            ),
            201
        );
    }

    private static JsonNode createUser(String email, String first, String last, boolean enabled) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", email.toLowerCase());
        body.put("email", email);
        body.put("firstName", first);
        body.put("lastName", last);
        body.put("password", USER_PASSWORD);
        body.put("source", userSource);
        body.put("enabled", true);
        body.put("preRegistration", false);
        body.put("registrationCompleted", true);
        body.put("additionalInformation", Map.of("app_roles", List.of("reader")));
        JsonNode user = json(mgmt("POST", MGMT + "/domains/" + domainId + "/users", body), 201);
        if (!enabled) {
            json(
                mgmt(
                    "PUT",
                    MGMT + "/domains/" + domainId + "/users/" + user.path("id").asText() + "/status",
                    Map.of("enabled", false)
                ),
                200
            );
        }
        return user;
    }

    private static void createClient(
        String clientId,
        List<String> grantTypes,
        List<Map<String, Object>> claims,
        List<String> identityProviders
    ) throws Exception {
        JsonNode app = json(
            mgmt(
                "POST",
                MGMT + "/domains/" + domainId + "/applications",
                Map.of("name", clientId, "type", "service", "clientId", clientId, "clientSecret", CLIENT_SECRET)
            ),
            201
        );
        Map<String, Object> oauth = new LinkedHashMap<>();
        oauth.put("grantTypes", grantTypes);
        oauth.put("tokenEndpointAuthMethod", "client_secret_post");
        oauth.put(
            "scopeSettings",
            List.of(Map.of("scope", "openid", "defaultScope", true), Map.of("scope", "mcp.read", "defaultScope", true))
        );
        oauth.put("tokenCustomClaims", claims);
        Map<String, Object> patch = new LinkedHashMap<>();
        patch.put("settings", Map.of("oauth", oauth));
        if (!identityProviders.isEmpty()) {
            patch.put(
                "identityProviders",
                identityProviders.stream().map(id -> Map.of("identity", id, "priority", 0)).collect(Collectors.toList())
            );
        }
        json(mgmt("PATCH", MGMT + "/domains/" + domainId + "/applications/" + app.path("id").asText(), patch), 200);
    }

    private static long countUsers() throws Exception {
        JsonNode page = json(mgmt("GET", MGMT + "/domains/" + domainId + "/users?page=0&size=100", null), 200);
        return page.path("totalCount").asLong();
    }

    private static void waitForGateway() throws Exception {
        String url = gatewayBase + "/" + domainPath + "/oidc/.well-known/openid-configuration";
        for (int i = 0; i < 120; i++) {
            if (get(url).statusCode() == 200) {
                return;
            }
            Thread.sleep(1000);
        }
        throw new IllegalStateException("Domain never came up on the gateway");
    }

    private static void waitForToken() throws Exception {
        // The grant and clients sync to the gateway independently; a malformed assertion is
        // refused by the plugin itself only once all of them are live.
        HttpResponse<String> probe = null;
        for (int i = 0; i < 60; i++) {
            probe = token("probe", Map.of());
            if (probe.body().contains("not a signed JWT")) {
                return;
            }
            Thread.sleep(1000);
        }
        throw new IllegalStateException("The ID-JAG grant never became active: " + probe.body());
    }

    // ------------------------------------------------------------- assertions

    private static void publishIssuer(String iss, ECKey key) throws Exception {
        WireMock wm = new WireMock(issuer.getHost(), issuer.getMappedPort(8080));
        wm.register(
            WireMock.get("/issuers/test-org/.well-known/openid-configuration").willReturn(
                WireMock.okJson(
                    MAPPER.writeValueAsString(
                        Map.of("issuer", iss, "jwks_uri", "http://issuer:8080/issuers/test-org/jwks")
                    )
                )
            )
        );
        wm.register(
            WireMock.get("/issuers/test-org/jwks").willReturn(
                WireMock.okJson(new JWKSet(key).toPublicJWKSet().toString())
            )
        );
    }

    private static JWTClaimsSet.Builder claims(Consumer<JWTClaimsSet.Builder> edit) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder b = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject("opaque-" + UUID.randomUUID())
            .audience(audience)
            .claim("client_id", CLIENT_ID)
            .claim("email", USER_EMAIL.toLowerCase())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(60)))
            .jwtID(UUID.randomUUID().toString());
        edit.accept(b);
        return b;
    }

    private static String assertion(Consumer<JWTClaimsSet.Builder> edit) throws Exception {
        return sign(claims(edit).build(), signingKey);
    }

    private static String sign(JWTClaimsSet claims, ECKey key) throws Exception {
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-id-jag+jwt"))
                .keyID(key.getKeyID())
                .build(),
            claims
        );
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static HttpResponse<String> token(String assertion, Map<String, String> extra) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
        params.put("assertion", assertion);
        params.put("client_id", CLIENT_ID);
        params.put("client_secret", CLIENT_SECRET);
        params.putAll(extra);
        return form("/" + domainPath + "/oauth/token", params);
    }

    private static void assertInvalidGrant(HttpResponse<String> res, String descriptionPart) throws Exception {
        assertThat(res.statusCode()).as(res.body()).isEqualTo(400);
        JsonNode body = MAPPER.readTree(res.body());
        assertThat(body.path("error").asText()).as(res.body()).isEqualTo("invalid_grant");
        assertThat(body.path("error_description").asText()).as(res.body()).contains(descriptionPart);
    }

    private static JsonNode payload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        return MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));
    }

    // ------------------------------------------------------------------ HTTP

    private static String adminLogin() throws Exception {
        String basic = Base64.getEncoder().encodeToString("admin:adminadmin".getBytes(StandardCharsets.UTF_8));
        HttpResponse<String> res = http.send(
            HttpRequest.newBuilder(URI.create(mgmtBase + "/management/auth/token"))
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
        return json(res, 200).path("access_token").asText();
    }

    private static HttpResponse<String> mgmt(String method, String path, Object body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(mgmtBase + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json");
        b.method(
            method,
            body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(body))
        );
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> get(String url) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> form(String path, Map<String, String> params) throws Exception {
        String body = params
            .entrySet()
            .stream()
            .map(
                e ->
                    URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) +
                    "=" +
                    URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)
            )
            .collect(Collectors.joining("&"));
        return http.send(
            HttpRequest.newBuilder(URI.create(gatewayBase + path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
    }

    private static JsonNode json(HttpResponse<String> res, int expected) throws Exception {
        if (res.statusCode() != expected && !(expected == 201 && res.statusCode() == 200)) {
            throw new IllegalStateException(
                res.request().method() + " " + res.request().uri() + " → " + res.statusCode() + ": " + res.body()
            );
        }
        return res.body() == null || res.body().isBlank() ? MAPPER.createObjectNode() : MAPPER.readTree(res.body());
    }

    private static Consumer<OutputFrame> logs(String prefix) {
        return frame -> {
            String line = frame.getUtf8StringWithoutLineEnding();
            if (line.isEmpty()) {
                return;
            }
            if (
                line.contains("io.fluenthealth") ||
                line.contains("IdJag") ||
                line.contains("id-jag") ||
                (line.contains(" ERROR ") &&
                    !line.contains("KubernetesConfig") &&
                    !line.contains("EmailNotifier") &&
                    !line.contains("metrics is disabled") &&
                    !line.contains("MongoUtils") &&
                    !line.contains("NodeHealthCheckMicrometerHandler"))
            ) {
                logger.info("[{}] {}", prefix, line);
            }
        };
    }
}
