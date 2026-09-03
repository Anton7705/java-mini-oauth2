package ru.yandex.practicum.oauth0.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private String secret = "dev-only-secret-change-me";

    private String issuer = "mini-auth";

    private String audience = "payments-api";

    private long accessTtlSec = 900;

    private long refreshTtlDays = 14;

    private long clockSkewSec = 60;

    private boolean seedDemoData = true;

    private RateLimit rateLimit = new RateLimit();

    public static class RateLimit {

        private boolean enabled = false;

        private int requestsPerMinute = 60;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getRequestsPerMinute() {
            return requestsPerMinute;
        }

        public void setRequestsPerMinute(int requestsPerMinute) {
            this.requestsPerMinute = requestsPerMinute;
        }
    }

    public long refreshTtlSeconds() {
        return refreshTtlDays * 24 * 60 * 60;
    }

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

    public long getAccessTtlSec() {
        return accessTtlSec;
    }

    public void setAccessTtlSec(long accessTtlSec) {
        this.accessTtlSec = accessTtlSec;
    }

    public long getRefreshTtlDays() {
        return refreshTtlDays;
    }

    public void setRefreshTtlDays(long refreshTtlDays) {
        this.refreshTtlDays = refreshTtlDays;
    }

    public long getClockSkewSec() {
        return clockSkewSec;
    }

    public void setClockSkewSec(long clockSkewSec) {
        this.clockSkewSec = clockSkewSec;
    }

    public boolean isSeedDemoData() {
        return seedDemoData;
    }

    public void setSeedDemoData(boolean seedDemoData) {
        this.seedDemoData = seedDemoData;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(RateLimit rateLimit) {
        this.rateLimit = rateLimit;
    }
}
