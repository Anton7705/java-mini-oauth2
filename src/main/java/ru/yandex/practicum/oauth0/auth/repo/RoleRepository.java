package ru.yandex.practicum.oauth0.auth.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.domain.RoleEntity;

public interface RoleRepository extends JpaRepository<RoleEntity, String> {
}
