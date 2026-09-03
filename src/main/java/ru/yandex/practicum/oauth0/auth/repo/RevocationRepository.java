package ru.yandex.practicum.oauth0.auth.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.domain.RevocationEntity;

public interface RevocationRepository extends JpaRepository<RevocationEntity, Long> {

    boolean existsByTokenTypeAndTokenRef(String tokenType, String tokenRef);

    void deleteByExpiresAtLessThan(long threshold);
}
