package ru.yandex.practicum.oauth0.auth.service;

import org.springframework.stereotype.Service;
import ru.yandex.practicum.oauth0.auth.domain.RoleEntity;
import ru.yandex.practicum.oauth0.auth.domain.UserEntity;
import ru.yandex.practicum.oauth0.auth.repo.RoleRepository;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class ScopeResolver {

    private final RoleRepository roles;

    public ScopeResolver(RoleRepository roles) {
        this.roles = roles;
    }

    public Set<String> scopesOfUser(UserEntity user) {
        Set<String> result = new LinkedHashSet<>();
        for (String roleName : user.getRoles()) {
            Optional<RoleEntity> role = roles.findById(roleName);
            role.ifPresent(r -> result.addAll(r.getScopes()));
        }
        return result;
    }

    public List<String> resolve(Collection<String> requested, Set<String> subjectScopes,
                                Set<String> clientScopes) {
        Set<String> available = new LinkedHashSet<>(subjectScopes);
        available.retainAll(clientScopes);

        if (available.isEmpty()) {
            throw OAuthException.forbidden("invalid_scope",
                    "no scopes are available for this subject and client combination");
        }
        if (requested == null || requested.isEmpty()) {
            return new ArrayList<>(available);
        }

        List<String> notAllowed = requested.stream()
                .filter(scope -> !available.contains(scope))
                .toList();
        if (!notAllowed.isEmpty()) {
            throw OAuthException.forbidden("invalid_scope", "scopes not allowed: " + notAllowed);
        }
        return new ArrayList<>(new LinkedHashSet<>(requested));
    }

    public static String asString(Collection<String> scopes) {
        return String.join(" ", scopes);
    }

    public static List<String> parse(String scopes) {
        if (scopes == null || scopes.isBlank()) {
            return List.of();
        }
        return List.of(scopes.trim().split("\\s+"));
    }
}
