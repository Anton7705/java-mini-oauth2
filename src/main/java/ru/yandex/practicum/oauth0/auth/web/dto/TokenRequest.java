package ru.yandex.practicum.oauth0.auth.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record TokenRequest(
        @JsonProperty("grant_type") String grantType,
        String username,
        String password,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("client_secret") String clientSecret,
        List<String> scopes,
        @JsonProperty("refresh_token") String refreshToken) {
}
