package ru.yandex.practicum.oauth0.rs.security;

import java.util.List;
import java.util.Set;

public record TokenPrincipal(
        String subject,
        String clientId,
        Set<String> scopes,
        Set<String> roles,
        String jti,
        long expiresAt) {

    public static final String ATTRIBUTE = "oauth0.principal";

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    public boolean hasAnyRole(List<String> candidates) {
        return candidates.stream().anyMatch(roles::contains);
    }
}
