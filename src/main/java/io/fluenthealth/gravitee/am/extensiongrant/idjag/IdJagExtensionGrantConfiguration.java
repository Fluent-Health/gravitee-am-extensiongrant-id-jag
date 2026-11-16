package io.fluenthealth.gravitee.am.extensiongrant.idjag;

import io.gravitee.am.extensiongrant.api.ExtensionGrantConfiguration;
import java.util.List;

/**
 * The extension grant's configuration, bound by AM from the JSON the management API stores. Field
 * names match {@code schemas/schema-form.json}.
 */
public class IdJagExtensionGrantConfiguration implements ExtensionGrantConfiguration {

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private String grantType = GRANT_TYPE;
    private String issuer;
    private String audience;
    private String tenant;
    private String domainId;
    private String dataPlaneId = "default";
    private String userSource;
    private List<String> allowedEmailDomains;
    private int clockSkewSeconds = 60;
    private int maxAssertionLifetimeSeconds = 300;
    private boolean allowInsecureIssuer = false;

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getDomainId() {
        return domainId;
    }

    public void setDomainId(String domainId) {
        this.domainId = domainId;
    }

    public String getDataPlaneId() {
        return dataPlaneId;
    }

    public void setDataPlaneId(String dataPlaneId) {
        this.dataPlaneId = dataPlaneId;
    }

    public String getUserSource() {
        return userSource;
    }

    public void setUserSource(String userSource) {
        this.userSource = userSource;
    }

    public List<String> getAllowedEmailDomains() {
        return allowedEmailDomains;
    }

    public void setAllowedEmailDomains(List<String> allowedEmailDomains) {
        this.allowedEmailDomains = allowedEmailDomains;
    }

    public int getClockSkewSeconds() {
        return clockSkewSeconds;
    }

    public void setClockSkewSeconds(int clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }

    public int getMaxAssertionLifetimeSeconds() {
        return maxAssertionLifetimeSeconds;
    }

    public void setMaxAssertionLifetimeSeconds(int maxAssertionLifetimeSeconds) {
        this.maxAssertionLifetimeSeconds = maxAssertionLifetimeSeconds;
    }

    public boolean isAllowInsecureIssuer() {
        return allowInsecureIssuer;
    }

    public void setAllowInsecureIssuer(boolean allowInsecureIssuer) {
        this.allowInsecureIssuer = allowInsecureIssuer;
    }
}
