package ru.yandex.practicum.oauth0.auth.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.domain.RefreshTokenEntity;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {
}
