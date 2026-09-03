package ru.yandex.practicum.oauth0.auth.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "clients")
public class ClientEntity {

    @Id
    @Column(name = "client_id", length = 64)
    private String clientId;

    @Column(name = "client_secret_hash", nullable = false, length = 100)
    private String clientSecretHash;

    @Column(name = "audience", nullable = false, length = 128)
    private String audience;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "description", length = 255)
    private String description;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_grants", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type", length = 32)
    private Set<String> allowedGrants = new LinkedHashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_scopes", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope", length = 128)
    private Set<String> allowedScopes = new LinkedHashSet<>();

    protected ClientEntity() {
    }

    public ClientEntity(String clientId, String clientSecretHash, String audience, String description,
                        Set<String> allowedGrants, Set<String> allowedScopes) {
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.audience = audience;
        this.description = description;
        this.allowedGrants = new LinkedHashSet<>(allowedGrants);
        this.allowedScopes = new LinkedHashSet<>(allowedScopes);
        this.enabled = true;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecretHash() {
        return clientSecretHash;
    }

    public String getAudience() {
        return audience;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getDescription() {
        return description;
    }

    public Set<String> getAllowedGrants() {
        return allowedGrants;
    }

    public Set<String> getAllowedScopes() {
        return allowedScopes;
    }
}
