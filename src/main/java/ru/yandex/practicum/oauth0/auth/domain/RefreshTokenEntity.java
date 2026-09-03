package ru.yandex.practicum.oauth0.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "refresh_index")
public class RefreshTokenEntity {

    @Id
    @Column(name = "refresh_id", length = 64)
    private String refreshId;

    @Column(name = "user_id", length = 64)
    private String userId;

    @Column(name = "client_id", nullable = false, length = 64)
    private String clientId;

    /** Space-delimited list, the same shape as the OAuth2 "scope" response field. */
    @Column(name = "scopes", nullable = false, length = 1024)
    private String scopes;

    @Column(name = "issued_at", nullable = false)
    private long issuedAt;

    @Column(name = "expires_at", nullable = false)
    private long expiresAt;

    @Column(name = "rotated", nullable = false)
    private boolean rotated;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    @Column(name = "replaced_by", length = 64)
    private String replacedBy;

    protected RefreshTokenEntity() {
    }

    public RefreshTokenEntity(String refreshId, String userId, String clientId, String scopes,
                              long issuedAt, long expiresAt) {
        this.refreshId = refreshId;
        this.userId = userId;
        this.clientId = clientId;
        this.scopes = scopes;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.rotated = false;
        this.revoked = false;
    }

    public String getRefreshId() {
        return refreshId;
    }

    public String getUserId() {
        return userId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getScopes() {
        return scopes;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public boolean isRotated() {
        return rotated;
    }

    public void setRotated(boolean rotated) {
        this.rotated = rotated;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public String getReplacedBy() {
        return replacedBy;
    }

    public void setReplacedBy(String replacedBy) {
        this.replacedBy = replacedBy;
    }
}
