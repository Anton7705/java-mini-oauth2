package ru.yandex.practicum.oauth0.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_events")
public class AuditEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Column(name = "outcome", nullable = false, length = 16)
    private String outcome;

    @Column(name = "client_id", length = 64)
    private String clientId;

    @Column(name = "user_id", length = 64)
    private String userId;

    @Column(name = "details", length = 512)
    private String details;

    @Column(name = "created_at", nullable = false)
    private long createdAt;

    protected AuditEventEntity() {
    }

    public AuditEventEntity(String eventType, String outcome, String clientId, String userId,
                            String details, long createdAt) {
        this.eventType = eventType;
        this.outcome = outcome;
        this.clientId = clientId;
        this.userId = userId;
        this.details = details;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public String getEventType() {
        return eventType;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getClientId() {
        return clientId;
    }

    public String getUserId() {
        return userId;
    }

    public String getDetails() {
        return details;
    }

    public long getCreatedAt() {
        return createdAt;
    }
}
