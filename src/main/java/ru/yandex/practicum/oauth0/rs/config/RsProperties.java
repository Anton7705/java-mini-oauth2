package ru.yandex.practicum.oauth0.rs.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "rs")
public class RsProperties {

    private String secret = "dev-only-secret-change-me";

    private String issuer = "mini-auth";

    private String audience = "payments-api";

    private long clockSkewSec = 60;

    private String authServerUrl = "http://localhost:8080";

    private boolean introspectionEnabled = true;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
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

    public long getClockSkewSec() {
        return clockSkewSec;
    }

    public void setClockSkewSec(long clockSkewSec) {
        this.clockSkewSec = clockSkewSec;
    }

    public String getAuthServerUrl() {
        return authServerUrl;
    }

    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }

    public boolean isIntrospectionEnabled() {
        return introspectionEnabled;
    }

    public void setIntrospectionEnabled(boolean introspectionEnabled) {
        this.introspectionEnabled = introspectionEnabled;
    }
}
