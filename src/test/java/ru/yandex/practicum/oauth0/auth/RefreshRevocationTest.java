package ru.yandex.practicum.oauth0.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import ru.yandex.practicum.oauth0.common.crypto.HmacSigner;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.support.AuthServerTest;
import ru.yandex.practicum.oauth0.support.TestSecrets;
import ru.yandex.practicum.oauth0.support.TestTokens;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AuthServerTest
class RefreshRevocationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private TokenCodec codec;

    @Autowired
    private TimeProvider time;

    @Test
    void refreshRotatesAndInvalidatesThePreviousToken() throws Exception {
        JsonNode first = login("alice", "pass");
        String originalRefresh = first.get("refresh_token").asText();

        JsonNode second = refresh(originalRefresh, status().isOk());
        String rotatedRefresh = second.get("refresh_token").asText();

        assertThat(rotatedRefresh).isNotEqualTo(originalRefresh);
        assertThat(second.get("access_token").asText()).isNotBlank();

        // reusing the rotated token is a replay: 409 and the whole family dies
        refresh(originalRefresh, status().isConflict());

        // the replacement issued from the compromised chain is dead too
        refresh(rotatedRefresh, status().isUnauthorized());
    }

    @Test
    void refreshWithAnotherClientIsRejected() throws Exception {
        String refreshToken = login("bob", "pass").get("refresh_token").asText();

        mvc.perform(post("/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "refresh_token",
                                  "refresh_token": "%s",
                                  "client_id": "svc-001",
                                  "client_secret": "svc-secret"
                                }""".formatted(refreshToken)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("unauthorized_client"));
    }

    @Test
    void refreshWithForeignSignatureIsUnauthorized() throws Exception {
        TokenCodec foreign = new TokenCodec(new HmacSigner(TestSecrets.WRONG_SECRET), mapper);
        long now = time.nowEpochSeconds();
        String forged = foreign.encode(TestTokens.refresh("u-100", now, now + 3600));

        refresh(forged, status().isUnauthorized());
    }

    @Test
    void revokedAccessTokenBecomesInactiveImmediately() throws Exception {
        String accessToken = login("alice", "pass").get("access_token").asText();

        introspect(accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.sub").value("u-100"))
                .andExpect(jsonPath("$.scopes[0]").value("payments:read"));

        mvc.perform(post("/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token": "%s", "token_type_hint": "access_token"}""".formatted(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));

        introspect(accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("revoked"));
    }

    @Test
    void revokedRefreshTokenCannotBeExchanged() throws Exception {
        String refreshToken = login("bob", "pass").get("refresh_token").asText();

        mvc.perform(post("/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token": "%s", "token_type_hint": "refresh_token"}""".formatted(refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));

        refresh(refreshToken, status().isUnauthorized());
    }

    @Test
    void introspectionReportsExpiredAndForgedTokensAsInactive() throws Exception {
        long now = time.nowEpochSeconds();

        String expired = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now - 7200, now - 3600));
        introspect(expired)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("expired"));

        TokenCodec foreign = new TokenCodec(new HmacSigner(TestSecrets.WRONG_SECRET), mapper);
        String forged = foreign.encode(TestTokens.access("u-100", List.of("payments:write"),
                List.of("admin"), now, now + 900));
        introspect(forged)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("bad_signature"));

        introspect("garbage")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("malformed"));
    }

    @Test
    void introspectionAppliesClockSkewToTheExpiryBoundary() throws Exception {
        long now = time.nowEpochSeconds();

        // expired 30 seconds ago, still inside the configured 60 second skew
        String justExpired = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now - 900, now - 30));
        introspect(justExpired).andExpect(jsonPath("$.active").value(true));

        // 120 seconds past expiry: beyond the skew
        String longExpired = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now - 1000, now - 120));
        introspect(longExpired)
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("expired"));

        // issued 30 seconds in the future, still acceptable
        String slightlyEarly = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now + 30, now + 900));
        introspect(slightlyEarly).andExpect(jsonPath("$.active").value(true));

        // issued 10 minutes in the future: the clock difference is too large
        String tooEarly = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now + 600, now + 1500));
        introspect(tooEarly)
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("not_yet_valid"));
    }

    @Test
    void revokingAnUnparsableTokenIsIdempotentAndDoesNotFail() throws Exception {
        mvc.perform(post("/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\": \"not-a-token\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(false));
    }

    // ------------------------------------------------------------------ tools

    private JsonNode login(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "password",
                                  "username": "%s",
                                  "password": "%s",
                                  "client_id": "cli-001",
                                  "client_secret": "secret"
                                }""".formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn();
        return mapper.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode refresh(String refreshToken,
                             org.springframework.test.web.servlet.ResultMatcher expected) throws Exception {
        MvcResult result = mvc.perform(post("/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "refresh_token",
                                  "refresh_token": "%s",
                                  "client_id": "cli-001",
                                  "client_secret": "secret"
                                }""".formatted(refreshToken)))
                .andExpect(expected)
                .andReturn();
        return mapper.readTree(result.getResponse().getContentAsString());
    }

    private org.springframework.test.web.servlet.ResultActions introspect(String token) throws Exception {
        return mvc.perform(post("/introspect")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(java.util.Map.of("token", token))));
    }
}
