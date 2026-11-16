package io.fluenthealth.gravitee.am.extensiongrant.idjag.user;

import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IdJagException;
import io.gravitee.am.dataplane.api.repository.UserRepository;
import io.gravitee.am.model.Domain;
import io.gravitee.am.model.User;
import io.gravitee.am.plugins.dataplane.core.DataPlaneRegistry;
import java.time.Duration;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Looks the user up in the domain's data plane by email, the way the ID-JAG profile asks
 * (whole address, case-insensitive), restricted to users whose {@code source} is the configured
 * identity provider.
 *
 * <p>{@link DataPlaneRegistry} is a node-level bean in the AM gateway, which a plugin's Spring
 * context inherits as its parent.
 */
public class DataPlaneUserLookup implements UserLookup {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final DataPlaneRegistry registry;
    private final Domain domain;
    private final String userSource;

    public DataPlaneUserLookup(DataPlaneRegistry registry, String domainId, String dataPlaneId, String userSource) {
        this.registry = registry;
        this.domain = new Domain();
        this.domain.setId(domainId);
        this.domain.setDataPlaneId(dataPlaneId);
        this.userSource = userSource;
    }

    @Override
    public User findByEmail(String email) throws IdJagException {
        UserRepository users = registry.getUserRepository(domain);
        // A non-strict lookup is case-insensitive. The Mongo data plane compiles the value as a
        // regex, so it is quoted and anchored there; the JDBC one compares UPPER() literals. The
        // exact comparison below is what decides either way.
        String pattern = users.getClass().getName().contains("Mongo") ? "^" + Pattern.quote(email) + "$" : email;
        List<User> found;
        try {
            found = users
                .findByDomainAndEmail(domain.getId(), pattern, false)
                .filter(u -> userSource.equals(u.getSource()))
                .filter(u -> u.getEmail() != null && u.getEmail().trim().equalsIgnoreCase(email))
                .toList()
                .timeout(TIMEOUT.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS)
                .blockingGet();
        } catch (RuntimeException e) {
            throw new IdJagException("User lookup failed", e);
        }
        if (found.isEmpty()) {
            throw new IdJagException("No user for this assertion");
        }
        if (found.size() > 1) {
            throw new IdJagException("More than one user for this assertion");
        }
        User user = found.get(0);
        if (!Boolean.TRUE.equals(user.isEnabled())) {
            throw new IdJagException("The user's account is disabled");
        }
        return user;
    }
}
