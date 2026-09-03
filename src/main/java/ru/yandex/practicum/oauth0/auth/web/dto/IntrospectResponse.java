package ru.yandex.practicum.oauth0.auth.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record IntrospectResponse(
        boolean active,
        String typ,
        String iss,
        String aud,
        String sub,
        @JsonProperty("client_id") String clientId,
        List<String> scopes,
        List<String> roles,
        Long iat,
        Long exp,
        String jti,
        String reason) {

    public static IntrospectResponse inactive(String reason) {
        return new IntrospectResponse(false, null, null, null, null, null, null, null, null, null, null, reason);
    }
}
