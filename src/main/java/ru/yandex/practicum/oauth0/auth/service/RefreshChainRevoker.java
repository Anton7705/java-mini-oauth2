package ru.yandex.practicum.oauth0.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.domain.RefreshTokenEntity;
import ru.yandex.practicum.oauth0.auth.domain.RevocationEntity;
import ru.yandex.practicum.oauth0.auth.repo.RefreshTokenRepository;
import ru.yandex.practicum.oauth0.auth.repo.RevocationRepository;

@Service
public class RefreshChainRevoker {

    private static final Logger log = LoggerFactory.getLogger(RefreshChainRevoker.class);

    private static final int MAX_CHAIN_LENGTH = 100;

    private final RefreshTokenRepository refreshTokens;
    private final RevocationRepository revocations;

    public RefreshChainRevoker(RefreshTokenRepository refreshTokens, RevocationRepository revocations) {
        this.refreshTokens = refreshTokens;
        this.revocations = revocations;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(String startRefreshId, long now) {
        RefreshTokenEntity current = refreshTokens.findById(startRefreshId).orElse(null);
        int visited = 0;

        while (current != null && visited++ < MAX_CHAIN_LENGTH) {
            current.setRevoked(true);
            refreshTokens.save(current);

            if (!revocations.existsByTokenTypeAndTokenRef(
                    RevocationEntity.TYPE_REFRESH, current.getRefreshId())) {
                revocations.save(new RevocationEntity(RevocationEntity.TYPE_REFRESH,
                        current.getRefreshId(), current.getExpiresAt(), now));
            }

            String next = current.getReplacedBy();
            current = next == null ? null : refreshTokens.findById(next).orElse(null);
        }

        if (visited >= MAX_CHAIN_LENGTH) {
            log.warn("stopped revoking the refresh family starting at {} after {} links",
                    startRefreshId, MAX_CHAIN_LENGTH);
        } else {
            log.warn("revoked a refresh token family of {} tokens starting at {}",
                    visited, startRefreshId);
        }
    }
}
