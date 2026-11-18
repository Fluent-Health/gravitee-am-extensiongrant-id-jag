package io.fluenthealth.gravitee.am.extensiongrant.idjag.user;

import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IdJagException;
import io.gravitee.am.dataplane.api.repository.UserRepository;
import io.gravitee.am.model.Domain;
import io.gravitee.am.model.User;
import io.gravitee.am.plugins.dataplane.core.DataPlaneRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Map;

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
        // Lookups in order, each filtered by the exact comparison below, which is what decides:
        //  1. AM's case-insensitive (non-strict) lookup with the plain address. Since AM 4.12.13
        //     the Mongo data plane quotes and anchors it itself (1.0.0 pre-quoted it, so 4.12.13
        //     searched for the quoted text and found nobody); before that it was an unanchored
        //     regex, which still finds the user. JDBC compares UPPER() literals.
        //  2. and 3. Exact-match (strict) lookups on the address as sent, then lower-cased, whose
        //     meaning doesn't change between versions: if AM changes non-strict matching again,
        //     everyone stored in lower case is still found.
        String lower = email.toLowerCase(java.util.Locale.ROOT);
        List<Map.Entry<String, Boolean>> attempts = new java.util.ArrayList<>();
        attempts.add(Map.entry(email, false));
        attempts.add(Map.entry(email, true));
        if (!lower.equals(email)) {
            attempts.add(Map.entry(lower, true));
        }
        List<User> found = List.of();
        try {
            for (Map.Entry<String, Boolean> attempt : attempts) {
                found = users
                    .findByDomainAndEmail(domain.getId(), attempt.getKey(), attempt.getValue())
                    .filter(u -> userSource.equals(u.getSource()))
                    .filter(u -> u.getEmail() != null && u.getEmail().trim().equalsIgnoreCase(email))
                    .toList()
                    .timeout(TIMEOUT.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS)
                    .blockingGet();
                if (!found.isEmpty()) {
                    break;
                }
            }
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
