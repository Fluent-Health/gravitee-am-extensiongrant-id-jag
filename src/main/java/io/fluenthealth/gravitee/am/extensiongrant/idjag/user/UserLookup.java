package io.fluenthealth.gravitee.am.extensiongrant.idjag.user;

import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IdJagException;
import io.gravitee.am.model.User;

/** Finds the one existing user an assertion's email names. Never creates users. */
public interface UserLookup {
    /**
     * @param email the assertion's email, lower-cased
     * @return the single matching, enabled user
     * @throws IdJagException when there is no such user, more than one, or the account is disabled
     */
    User findByEmail(String email) throws IdJagException;
}
