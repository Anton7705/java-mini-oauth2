package ru.yandex.practicum.oauth0.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.domain.AuditEventEntity;
import ru.yandex.practicum.oauth0.auth.repo.AuditEventRepository;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    public static final String OUTCOME_SUCCESS = "success";
    public static final String OUTCOME_FAILURE = "failure";

    private final AuditEventRepository repository;
    private final TimeProvider time;

    public AuditService(AuditEventRepository repository, TimeProvider time) {
        this.repository = repository;
        this.time = time;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void success(String eventType, String clientId, String userId, String details) {
        record(eventType, OUTCOME_SUCCESS, clientId, userId, details);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void failure(String eventType, String clientId, String userId, String details) {
        record(eventType, OUTCOME_FAILURE, clientId, userId, details);
    }

    private void record(String eventType, String outcome, String clientId, String userId, String details) {
        String safeDetails = truncate(details);
        if (OUTCOME_FAILURE.equals(outcome)) {
            log.warn("audit event={} outcome={} client={} user={} details={}",
                    eventType, outcome, clientId, userId, safeDetails);
        } else {
            log.info("audit event={} outcome={} client={} user={} details={}",
                    eventType, outcome, clientId, userId, safeDetails);
        }
        try {
            repository.save(new AuditEventEntity(eventType, outcome, clientId, userId,
                    safeDetails, time.nowEpochSeconds()));
        } catch (RuntimeException e) {
            // auditing must never break the request it describes
            log.error("failed to persist audit event {}", eventType, e);
        }
    }

    private String truncate(String details) {
        if (details == null) {
            return null;
        }
        return details.length() <= 512 ? details : details.substring(0, 512);
    }
}
