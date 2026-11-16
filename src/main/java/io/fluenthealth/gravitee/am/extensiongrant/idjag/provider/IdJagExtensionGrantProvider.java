package io.fluenthealth.gravitee.am.extensiongrant.idjag.provider;

import io.fluenthealth.gravitee.am.extensiongrant.idjag.IdJagExtensionGrantConfiguration;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.user.DataPlaneUserLookup;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.user.UserLookup;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IdJagException;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IdJagValidator;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IssuerKeySource;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.ReplayCache;
import io.gravitee.am.common.plugin.ValidationResult;
import io.gravitee.am.extensiongrant.api.ExtensionGrantProvider;
import io.gravitee.am.extensiongrant.api.exceptions.InvalidGrantException;
import io.gravitee.am.identityprovider.api.DefaultUser;
import io.gravitee.am.identityprovider.api.User;
import io.gravitee.am.plugins.dataplane.core.DataPlaneRegistry;
import io.gravitee.am.repository.oauth2.model.request.TokenRequest;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.schedulers.Schedulers;
import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Accepts an ID-JAG on the JWT-bearer grant and returns the existing user it names.
 *
 * <p>The returned principal carries the stored user's {@code externalId} as its id, with its
 * username, names and dynamic roles and groups, and no extra claims. With the extension grant set
 * to create users and its identity provider set to {@code userSource}, AM's connect step then finds
 * that same record by {@code (externalId, source)}, re-checks that the account is enabled, and
 * issues the token from the stored user, so its {@code sub} and custom claims are the ones a normal
 * sign-in produces. Because the plugin only ever returns a user it found, nothing is created.
 */
public class IdJagExtensionGrantProvider implements ExtensionGrantProvider, InitializingBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(IdJagExtensionGrantProvider.class);
    private static final String ASSERTION = "assertion";
    private static final int REPLAY_CACHE_SIZE = 100_000;

    @Autowired
    private IdJagExtensionGrantConfiguration configuration;

    @Autowired(required = false)
    private DataPlaneRegistry dataPlaneRegistry;

    private IdJagValidator validator;
    private UserLookup userLookup;

    public IdJagExtensionGrantProvider() {}

    /** For tests: wire the collaborators directly. */
    public IdJagExtensionGrantProvider(IdJagValidator validator, UserLookup userLookup) {
        this.validator = validator;
        this.userLookup = userLookup;
    }

    @Override
    public void afterPropertiesSet() {
        String problem = configurationProblem(configuration);
        if (problem != null) {
            // Leave the provider inert: every grant is refused with this message.
            LOGGER.error("ID-JAG extension grant is misconfigured: {}", problem);
            return;
        }
        Clock clock = Clock.systemUTC();
        validator = new IdJagValidator(
            new IdJagValidator.Settings(
                configuration.getIssuer(),
                configuration.getAudience(),
                configuration.getTenant(),
                configuration.getAllowedEmailDomains(),
                configuration.getClockSkewSeconds(),
                configuration.getMaxAssertionLifetimeSeconds()
            ),
            new IssuerKeySource(configuration.getIssuer(), configuration.isAllowInsecureIssuer(), clock),
            new ReplayCache(REPLAY_CACHE_SIZE, clock),
            clock
        );
        if (dataPlaneRegistry == null) {
            LOGGER.error("ID-JAG extension grant: no DataPlaneRegistry bean in the plugin's parent context");
            return;
        }
        userLookup = new DataPlaneUserLookup(
            dataPlaneRegistry,
            configuration.getDomainId(),
            configuration.getDataPlaneId(),
            configuration.getUserSource()
        );
        LOGGER.info(
            "ID-JAG extension grant ready: issuer {}, audience {}, domain {}",
            configuration.getIssuer(),
            configuration.getAudience(),
            configuration.getDomainId()
        );
    }

    @Override
    public ValidationResult validate() {
        String problem = configurationProblem(configuration);
        return problem == null ? ValidationResult.SUCCEEDED : ValidationResult.invalid(problem);
    }

    @Override
    public Maybe<User> grant(TokenRequest tokenRequest) {
        return Maybe.fromCallable(() -> resolve(tokenRequest)).subscribeOn(Schedulers.io());
    }

    User resolve(TokenRequest tokenRequest) {
        if (validator == null || userLookup == null) {
            throw new InvalidGrantException("The ID-JAG grant is not configured");
        }
        String assertion = tokenRequest.getRequestParameters() == null
            ? null
            : tokenRequest.getRequestParameters().get(ASSERTION);
        try {
            IdJagValidator.ValidatedAssertion valid = validator.validate(
                assertion,
                tokenRequest.getClientId(),
                tokenRequest.getScope()
            );
            io.gravitee.am.model.User stored = userLookup.findByEmail(valid.email());
            LOGGER.debug("ID-JAG accepted for client {} (jti {})", tokenRequest.getClientId(), valid.jti());
            return principalFor(stored);
        } catch (IdJagException e) {
            LOGGER.info("ID-JAG refused for client {}: {}", tokenRequest.getClientId(), e.getMessage());
            throw new InvalidGrantException(e.getMessage());
        }
    }

    static User principalFor(io.gravitee.am.model.User stored) {
        DefaultUser principal = new DefaultUser(stored.getUsername());
        principal.setId(stored.getExternalId());
        principal.setEmail(stored.getEmail());
        principal.setFirstName(stored.getFirstName());
        principal.setLastName(stored.getLastName());
        principal.setRoles(stored.getDynamicRoles() == null ? null : new ArrayList<>(stored.getDynamicRoles()));
        principal.setGroups(stored.getDynamicGroups() == null ? null : new ArrayList<>(stored.getDynamicGroups()));
        // Empty on purpose: connect merges these over the stored record, so anything put here
        // would overwrite what the identity provider and SCIM wrote.
        principal.setAdditionalInformation(new HashMap<>());
        return principal;
    }

    static String configurationProblem(IdJagExtensionGrantConfiguration c) {
        if (c == null) {
            return "no configuration";
        }
        if (!IdJagExtensionGrantConfiguration.GRANT_TYPE.equals(c.getGrantType())) {
            return "grantType must be " + IdJagExtensionGrantConfiguration.GRANT_TYPE;
        }
        if (isBlank(c.getIssuer())) {
            return "issuer is required";
        }
        String scheme = schemeOf(c.getIssuer());
        if (!"https".equals(scheme) && !(c.isAllowInsecureIssuer() && "http".equals(scheme))) {
            return "issuer must be an https URL";
        }
        if (isBlank(c.getAudience())) {
            return "audience is required";
        }
        if (isBlank(c.getDomainId())) {
            return "domainId is required";
        }
        if (isBlank(c.getDataPlaneId())) {
            return "dataPlaneId is required";
        }
        if (isBlank(c.getUserSource())) {
            return "userSource is required";
        }
        if (c.getClockSkewSeconds() < 0 || c.getClockSkewSeconds() > 300) {
            return "clockSkewSeconds must be between 0 and 300";
        }
        if (c.getMaxAssertionLifetimeSeconds() <= 0 || c.getMaxAssertionLifetimeSeconds() > 3600) {
            return "maxAssertionLifetimeSeconds must be between 1 and 3600";
        }
        return null;
    }

    private static String schemeOf(String url) {
        try {
            String s = URI.create(url).getScheme();
            return s == null ? null : s.toLowerCase(java.util.Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
