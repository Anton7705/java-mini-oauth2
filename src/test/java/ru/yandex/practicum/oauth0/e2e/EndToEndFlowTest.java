package ru.yandex.practicum.oauth0.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
import ru.yandex.practicum.oauth0.rs.ResourceApp;
import ru.yandex.practicum.oauth0.support.TestSecrets;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class EndToEndFlowTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final TestRestTemplate http = new TestRestTemplate();

    private ConfigurableApplicationContext auth;
    private ConfigurableApplicationContext rs;
    private String authUrl;
    private String rsUrl;

    @BeforeEach
    void startBothApplications() {
        String database = "jdbc:h2:mem:e2e-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";

        auth = new SpringApplicationBuilder(AuthApp.class).run(
                "--server.port=0",
                "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.datasource.url=" + database,
                "--spring.datasource.username=sa",
                "--spring.datasource.password=",
                "--auth.secret=" + TestSecrets.SECRET,
                "--auth.seed-demo-data=true");
        authUrl = "http://localhost:" + portOf(auth);

        rs = new SpringApplicationBuilder(ResourceApp.class).run(
                "--server.port=0",
                "--rs.secret=" + TestSecrets.SECRET,
                "--rs.introspection-enabled=true",
                "--rs.auth-server-url=" + authUrl);
        rsUrl = "http://localhost:" + portOf(rs);
    }

    @AfterEach
    void stopBothApplications() {
        if (rs != null) {
            rs.close();
        }
        if (auth != null) {
            auth.close();
        }
    }

    @Test
    void passwordGrantThenResourceAccessThenRevocation() throws Exception {
        ResponseEntity<String> login = postJson(authUrl + "/token", """
                {
                  "grant_type": "password",
                  "username": "bob",
                  "password": "pass",
                  "client_id": "cli-001",
                  "client_secret": "secret",
                  "scopes": ["payments:read", "payments:write"]
                }""");
        assertThat(login.getStatusCode().value()).isEqualTo(200);

        JsonNode tokens = mapper.readTree(login.getBody());
        String accessToken = tokens.get("access_token").asText();
        String refreshToken = tokens.get("refresh_token").asText();

        assertThat(get(rsUrl + "/api/payments", accessToken).getStatusCode().value()).isEqualTo(200);

        ResponseEntity<String> created = postJson(rsUrl + "/api/payments",
                "{\"amount_minor\": 12500, \"currency\": \"RUB\"}", accessToken);
        assertThat(created.getStatusCode().value()).isEqualTo(201);

        // an admin-only operation is refused for an editor
        assertThat(exchange(rsUrl + "/api/payments/pay-1", HttpMethod.DELETE, accessToken)
                .getStatusCode().value()).isEqualTo(403);

        // rotate the session, then revoke the fresh access token
        ResponseEntity<String> rotated = postJson(authUrl + "/token/refresh", """
                {
                  "grant_type": "refresh_token",
                  "refresh_token": "%s",
                  "client_id": "cli-001",
                  "client_secret": "secret"
                }""".formatted(refreshToken));
        assertThat(rotated.getStatusCode().value()).isEqualTo(200);

        String rotatedAccess = mapper.readTree(rotated.getBody()).get("access_token").asText();
        assertThat(get(rsUrl + "/api/payments", rotatedAccess).getStatusCode().value()).isEqualTo(200);

        ResponseEntity<String> revoked = postJson(authUrl + "/revoke",
                "{\"token\": \"%s\", \"token_type_hint\": \"access_token\"}".formatted(rotatedAccess));
        assertThat(revoked.getStatusCode().value()).isEqualTo(200);

        // the signature is still valid, but introspection now reports the token as dead
        assertThat(get(rsUrl + "/api/payments", rotatedAccess).getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void clientCredentialsTokenCanReadButNotWrite() throws Exception {
        ResponseEntity<String> login = postJson(authUrl + "/token", """
                {
                  "grant_type": "client_credentials",
                  "client_id": "svc-001",
                  "client_secret": "svc-secret"
                }""");
        assertThat(login.getStatusCode().value()).isEqualTo(200);

        JsonNode body = mapper.readTree(login.getBody());
        assertThat(body.hasNonNull("refresh_token")).isFalse();
        String accessToken = body.get("access_token").asText();

        assertThat(get(rsUrl + "/api/payments", accessToken).getStatusCode().value()).isEqualTo(200);
        assertThat(postJson(rsUrl + "/api/payments", "{\"amount_minor\": 100}", accessToken)
                .getStatusCode().value()).isEqualTo(403);
    }

    // ------------------------------------------------------------------ tools

    private int portOf(ConfigurableApplicationContext context) {
        return ((ServletWebServerApplicationContext) context).getWebServer().getPort();
    }

    private ResponseEntity<String> postJson(String url, String body) {
        return postJson(url, body, null);
    }

    private ResponseEntity<String> postJson(String url, String body, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (accessToken != null) {
            headers.setBearerAuth(accessToken);
        }
        return http.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    }

    private ResponseEntity<String> get(String url, String accessToken) {
        return exchange(url, HttpMethod.GET, accessToken);
    }

    private ResponseEntity<String> exchange(String url, HttpMethod method, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return http.exchange(url, method, new HttpEntity<>(headers), String.class);
    }
}
