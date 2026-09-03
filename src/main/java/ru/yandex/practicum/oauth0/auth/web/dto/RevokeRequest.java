package ru.yandex.practicum.oauth0.auth.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RevokeRequest(
        String token,
        @JsonProperty("token_type_hint") String tokenTypeHint) {
}
