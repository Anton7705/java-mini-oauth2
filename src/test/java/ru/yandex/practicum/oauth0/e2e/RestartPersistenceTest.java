package ru.yandex.practicum.oauth0.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import ru.yandex.practicum.oauth0.auth.AuthApp;
import ru.yandex.practicum.oauth0.support.TestSecrets;

import java.nio.file.Path;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RestartPersistenceTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final TestRestTemplate http = new TestRestTemplate();

    @Test
    void refreshAndRevocationStateSurviveARestart() throws Exception {
        Path databaseFile = Path.of("target", "test-db", "restart-" + UUID.randomUUID());
        String url = "jdbc:h2:file:./" + databaseFile.toString().replace('\\', '/');

        String refreshToken;
        String revokedAccessToken;

        ConfigurableApplicationContext first = start(url);
        try {
            String base = "http://localhost:" + portOf(first);

            JsonNode session = mapper.readTree(postJson(base + "/token", """
                    {
                      "grant_type": "password",
                      "username": "alice",
                      "password": "pass",
                      "client_id": "cli-001",
                      "client_secret": "secret"
                    }""").getBody());
            refreshToken = session.get("refresh_token").asText();
            revokedAccessToken = session.get("access_token").asText();

            ResponseEntity<String> revoked = postJson(base + "/revoke",
                    "{\"token\": \"%s\"}".formatted(revokedAccessToken));
            assertThat(revoked.getStatusCode().value()).isEqualTo(200);
        } finally {
            first.close();
        }

        ConfigurableApplicationContext second = start(url);
        try {
            String base = "http://localhost:" + portOf(second);

            // the refresh token issued by the previous process is still exchangeable
            ResponseEntity<String> rotated = postJson(base + "/token/refresh", """
                    {
                      "grant_type": "refresh_token",
                      "refresh_token": "%s",
                      "client_id": "cli-001",
                      "client_secret": "secret"
                    }""".formatted(refreshToken));
            assertThat(rotated.getStatusCode().value()).isEqualTo(200);
            assertThat(mapper.readTree(rotated.getBody()).get("access_token").asText()).isNotBlank();

            // and the revocation recorded before the restart is still in force
            JsonNode introspection = mapper.readTree(postJson(base + "/introspect",
                    "{\"token\": \"%s\"}".formatted(revokedAccessToken)).getBody());
            assertThat(introspection.get("active").asBoolean()).isFalse();
            assertThat(introspection.get("reason").asText()).isEqualTo("revoked");

            // the token that was just rotated cannot be replayed either
            ResponseEntity<String> replay = postJson(base + "/token/refresh", """
                    {
                      "grant_type": "refresh_token",
                      "refresh_token": "%s",
                      "client_id": "cli-001",
                      "client_secret": "secret"
                    }""".formatted(refreshToken));
            assertThat(replay.getStatusCode().value()).isEqualTo(409);
        } finally {
            second.close();
        }
    }

    private ConfigurableApplicationContext start(String databaseUrl) {
        return new SpringApplicationBuilder(AuthApp.class).run(
                "--server.port=0",
                "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.datasource.url=" + databaseUrl,
                "--spring.datasource.username=sa",
                "--spring.datasource.password=",
                "--auth.secret=" + TestSecrets.SECRET,
                "--auth.seed-demo-data=true");
    }

    private int portOf(ConfigurableApplicationContext context) {
        return ((ServletWebServerApplicationContext) context).getWebServer().getPort();
    }

    private ResponseEntity<String> postJson(String url, String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return http.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    }
}
