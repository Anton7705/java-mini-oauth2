package ru.yandex.practicum.oauth0.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ApplicationArguments;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.config.AuthProperties;
import ru.yandex.practicum.oauth0.auth.domain.ClientEntity;
import ru.yandex.practicum.oauth0.auth.domain.RoleEntity;
import ru.yandex.practicum.oauth0.auth.domain.UserEntity;
import ru.yandex.practicum.oauth0.auth.repo.ClientRepository;
import ru.yandex.practicum.oauth0.auth.repo.RoleRepository;
import ru.yandex.practicum.oauth0.auth.repo.UserRepository;
import ru.yandex.practicum.oauth0.common.crypto.PasswordHasher;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;

import java.util.Set;

@Component
public class DemoDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

    private final RoleRepository roles;
    private final UserRepository users;
    private final ClientRepository clients;
    private final PasswordHasher hasher;
    private final TimeProvider time;
    private final AuthProperties props;

    public DemoDataSeeder(RoleRepository roles, UserRepository users, ClientRepository clients,
                          PasswordHasher hasher, TimeProvider time, AuthProperties props) {
        this.roles = roles;
        this.users = users;
        this.clients = clients;
        this.hasher = hasher;
        this.time = time;
        this.props = props;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!props.isSeedDemoData()) {
            return;
        }

        seedRole("viewer", "read-only access to payments", Set.of("payments:read"));
        seedRole("editor", "read and write payments", Set.of("payments:read", "payments:write"));
        seedRole("admin", "full access to payments",
                Set.of("payments:read", "payments:write", "payments:admin"));

        long now = time.nowEpochSeconds();
        seedUser("u-100", "alice", "pass", Set.of("viewer"), now);
        seedUser("u-200", "bob", "pass", Set.of("editor"), now);
        seedUser("u-300", "root", "root-pass", Set.of("admin"), now);

        seedClient("cli-001", "secret", "payments-api", "demo web application",
                Set.of(TokenService.GRANT_PASSWORD, TokenService.GRANT_REFRESH_TOKEN),
                Set.of("payments:read", "payments:write", "payments:admin"));
        seedClient("svc-001", "svc-secret", "payments-api", "machine-to-machine job",
                Set.of(TokenService.GRANT_CLIENT_CREDENTIALS),
                Set.of("payments:read"));
    }

    private void seedRole(String name, String description, Set<String> scopes) {
        if (roles.existsById(name)) {
            return;
        }
        roles.save(new RoleEntity(name, description, scopes));
        log.info("seeded role {} with scopes {}", name, scopes);
    }

    private void seedUser(String userId, String username, String password, Set<String> userRoles, long now) {
        if (users.findByUsername(username).isPresent()) {
            return;
        }
        users.save(new UserEntity(userId, username, hasher.hash(password), userRoles, now));
        log.info("seeded user {} with roles {}", username, userRoles);
    }

    private void seedClient(String clientId, String secret, String audience, String description,
                            Set<String> grants, Set<String> scopes) {
        if (clients.existsById(clientId)) {
            return;
        }
        clients.save(new ClientEntity(clientId, hasher.hash(secret), audience, description, grants, scopes));
        log.info("seeded client {} with grants {}", clientId, grants);
    }
}
