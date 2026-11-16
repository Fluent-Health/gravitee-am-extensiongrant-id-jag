package io.fluenthealth.gravitee.am.extensiongrant.idjag.validation;

/**
 * An assertion was refused. The message goes back to the client as the invalid_grant
 * error_description, so it names the failed check and never echoes key material.
 */
public class IdJagException extends Exception {

    public IdJagException(String message) {
        super(message);
    }

    public IdJagException(String message, Throwable cause) {
        super(message, cause);
    }
}
