package ru.yandex.practicum.oauth0.rs.web.dto;

public record Payment(String id, String owner, long amountMinor, String currency, String description) {
}
