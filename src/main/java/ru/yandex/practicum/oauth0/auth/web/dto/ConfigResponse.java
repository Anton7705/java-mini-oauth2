package ru.yandex.practicum.oauth0.auth.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ConfigResponse(
        String issuer,
        String aud,
        @JsonProperty("access_ttl_sec") long accessTtlSec,
        @JsonProperty("refresh_ttl_days") long refreshTtlDays,
        @JsonProperty("token_alg") String tokenAlg) {
}
