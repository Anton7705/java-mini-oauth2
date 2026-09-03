package ru.yandex.practicum.oauth0.auth.web.dto;

public record RevokeResponse(boolean revoked, String detail) {
}
