package io.fluenthealth.gravitee.am.extensiongrant.idjag;

import io.fluenthealth.gravitee.am.extensiongrant.idjag.provider.IdJagExtensionGrantProvider;
import io.gravitee.am.extensiongrant.api.ExtensionGrant;

/** Plugin entry point: binds the configuration class to the provider. */
public class IdJagExtensionGrant extends ExtensionGrant<IdJagExtensionGrantConfiguration, IdJagExtensionGrantProvider> {

    @Override
    public Class<IdJagExtensionGrantConfiguration> configuration() {
        return IdJagExtensionGrantConfiguration.class;
    }

    @Override
    public Class<IdJagExtensionGrantProvider> provider() {
        return IdJagExtensionGrantProvider.class;
    }
}
