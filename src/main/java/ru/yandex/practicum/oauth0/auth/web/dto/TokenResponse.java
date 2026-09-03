package ru.yandex.practicum.oauth0.auth.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        String scope) {

    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, String scope) {
        return new TokenResponse(accessToken, refreshToken, "Bearer", expiresIn, scope);
    }
}
