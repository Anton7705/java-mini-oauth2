package ru.yandex.practicum.oauth0.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "revocation")
public class RevocationEntity {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "token_type", nullable = false, length = 16)
    private String tokenType;

    @Column(name = "token_ref", nullable = false, length = 64)
    private String tokenRef;

    @Column(name = "expires_at", nullable = false)
    private long expiresAt;

    @Column(name = "revoked_at", nullable = false)
    private long revokedAt;

    protected RevocationEntity() {
    }

    public RevocationEntity(String tokenType, String tokenRef, long expiresAt, long revokedAt) {
        this.tokenType = tokenType;
        this.tokenRef = tokenRef;
        this.expiresAt = expiresAt;
        this.revokedAt = revokedAt;
    }

    public Long getId() {
        return id;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getTokenRef() {
        return tokenRef;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public long getRevokedAt() {
        return revokedAt;
    }
}
