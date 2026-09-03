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
@Table(name = "roles")
public class RoleEntity {

    @Id
    @Column(name = "role_name", length = 64)
    private String roleName;

    @Column(name = "description", length = 255)
    private String description;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "role_scopes", joinColumns = @JoinColumn(name = "role_name"))
    @Column(name = "scope", length = 128)
    private Set<String> scopes = new LinkedHashSet<>();

    protected RoleEntity() {
    }

    public RoleEntity(String roleName, String description, Set<String> scopes) {
        this.roleName = roleName;
        this.description = description;
        this.scopes = new LinkedHashSet<>(scopes);
    }

    public String getRoleName() {
        return roleName;
    }

    public String getDescription() {
        return description;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
