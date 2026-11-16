package io.fluenthealth.gravitee.am.extensiongrant.idjag.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.fluenthealth.gravitee.am.extensiongrant.idjag.IdJagExtensionGrantConfiguration;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.user.UserLookup;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IdJagException;
import io.fluenthealth.gravitee.am.extensiongrant.idjag.validation.IdJagValidator;
import io.gravitee.am.extensiongrant.api.exceptions.InvalidGrantException;
import io.gravitee.am.model.User;
import io.gravitee.am.repository.oauth2.model.request.TokenRequest;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class IdJagExtensionGrantProviderTest {

    @Test
    void returnsThePrincipalConnectWillMatchOnAndNothingElse() throws Exception {
        IdJagValidator validator = mock(IdJagValidator.class);
        UserLookup lookup = mock(UserLookup.class);
        when(validator.validate(any(), any(), any())).thenReturn(
            new IdJagValidator.ValidatedAssertion("sub", "ada@example.com", "jti", null)
        );
        User stored = new User();
        stored.setId("am-user-id");
        stored.setExternalId("idp-subject");
        stored.setUsername("ada@example.com");
        stored.setEmail("Ada@Example.com");
        stored.setFirstName("Ada");
        stored.setLastName("Lovelace");
        stored.setDynamicRoles(List.of("r1"));
        stored.setAdditionalInformation(Map.of("app_roles", List.of("reader")));
        when(lookup.findByEmail("ada@example.com")).thenReturn(stored);

        var principal = new IdJagExtensionGrantProvider(validator, lookup).resolve(request("assertion-value"));

        assertThat(principal.getId()).isEqualTo("idp-subject");
        assertThat(principal.getUsername()).isEqualTo("ada@example.com");
        assertThat(principal.getEmail()).isEqualTo("Ada@Example.com");
        assertThat(principal.getFirstName()).isEqualTo("Ada");
        assertThat(principal.getRoles()).containsExactly("r1");
        // Never carries stored claims back: connect merges these over the record.
        assertThat(principal.getAdditionalInformation()).isEmpty();
    }

    @Test
    void turnsARefusalIntoInvalidGrantAndNeverLooksTheUserUp() throws Exception {
        IdJagValidator validator = mock(IdJagValidator.class);
        UserLookup lookup = mock(UserLookup.class);
        when(validator.validate(any(), any(), any())).thenThrow(new IdJagException("Assertion audience is wrong"));

        var provider = new IdJagExtensionGrantProvider(validator, lookup);
        assertThatThrownBy(() -> provider.resolve(request("x")))
            .isInstanceOf(InvalidGrantException.class)
            .hasMessage("Assertion audience is wrong");
        verify(lookup, never()).findByEmail(anyString());
    }

    @Test
    void refusesEverythingWhenUnconfigured() {
        var provider = new IdJagExtensionGrantProvider(null, null);
        assertThatThrownBy(() -> provider.resolve(request("x"))).isInstanceOf(InvalidGrantException.class);
    }

    @Test
    void validatesConfiguration() {
        IdJagExtensionGrantConfiguration c = new IdJagExtensionGrantConfiguration();
        assertThat(IdJagExtensionGrantProvider.configurationProblem(c)).contains("issuer");
        c.setIssuer("http://identity.example/issuers/x");
        assertThat(IdJagExtensionGrantProvider.configurationProblem(c)).contains("https");
        c.setIssuer("https://identity.example/issuers/x");
        assertThat(IdJagExtensionGrantProvider.configurationProblem(c)).contains("audience");
        c.setAudience("https://auth.example/staff/oidc");
        assertThat(IdJagExtensionGrantProvider.configurationProblem(c)).contains("domainId");
        c.setDomainId("d");
        assertThat(IdJagExtensionGrantProvider.configurationProblem(c)).contains("userSource");
        c.setUserSource("corporate-idp");
        assertThat(IdJagExtensionGrantProvider.configurationProblem(c)).isNull();
        c.setGrantType("urn:ietf:params:oauth:grant-type:token-exchange");
        assertThat(IdJagExtensionGrantProvider.configurationProblem(c)).contains("grantType");
    }

    private static TokenRequest request(String assertion) {
        TokenRequest r = new TokenRequest();
        r.setClientId("mcp-client");
        r.setScope(Set.of("mcp.read"));
        r.setRequestParameters(
            Map.of("grant_type", IdJagExtensionGrantConfiguration.GRANT_TYPE, "assertion", assertion)
        );
        return r;
    }
}
