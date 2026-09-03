package ru.yandex.practicum.oauth0.rs.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;

public class RemoteTokenIntrospector implements TokenIntrospector {

    private static final Logger log = LoggerFactory.getLogger(RemoteTokenIntrospector.class);

    private final RestClient client;
    private final String authServerUrl;

    public RemoteTokenIntrospector(String authServerUrl) {
        this.authServerUrl = authServerUrl;
        this.client = RestClient.create();
    }

    @Override
    public boolean isActive(String token) {
        try {
            Map<?, ?> body = client.post()
                    .uri(authServerUrl + "/introspect")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("token", token))
                    .retrieve()
                    .body(Map.class);
            return body != null && Boolean.TRUE.equals(body.get("active"));
        } catch (RestClientException e) {
            log.error("introspection call to {} failed", authServerUrl, e);
            throw new IntrospectionUnavailableException("authorization server is unreachable", e);
        }
    }
}
