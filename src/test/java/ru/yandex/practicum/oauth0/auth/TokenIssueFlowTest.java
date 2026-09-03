package ru.yandex.practicum.oauth0.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import ru.yandex.practicum.oauth0.common.token.TokenClaims;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.common.token.TokenKind;
import ru.yandex.practicum.oauth0.support.AuthServerTest;
import ru.yandex.practicum.oauth0.support.TestSecrets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AuthServerTest
class TokenIssueFlowTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private TokenCodec codec;

    @Test
    void passwordGrantIssuesAccessAndRefresh() throws Exception {
        MvcResult result = mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "password",
                                  "username": "alice",
                                  "password": "pass",
                                  "client_id": "cli-001",
                                  "client_secret": "secret",
                                  "scopes": ["payments:read"]
                                }"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.scope").value("payments:read"))
                .andReturn();

        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("access_token").asText()).isNotBlank();
        assertThat(body.get("refresh_token").asText()).isNotBlank();

        TokenClaims access = codec.decodeAndVerify(body.get("access_token").asText());
        assertThat(access.getTyp()).isEqualTo(TokenKind.ACCESS);
        assertThat(access.getIss()).isEqualTo(TestSecrets.ISSUER);
        assertThat(access.getAud()).isEqualTo(TestSecrets.AUDIENCE);
        assertThat(access.getSub()).isEqualTo("u-100");
        assertThat(access.getClientId()).isEqualTo("cli-001");
        assertThat(access.getRoles()).containsExactly("viewer");
        assertThat(access.getJti()).isNotBlank();
        assertThat(access.getExp() - access.getIat()).isEqualTo(900L);

        // the refresh token is bound to the auth server itself, never to the resource API
        TokenClaims refresh = codec.decodeAndVerify(body.get("refresh_token").asText());
        assertThat(refresh.getTyp()).isEqualTo(TokenKind.REFRESH);
        assertThat(refresh.getAud()).isEqualTo(TestSecrets.ISSUER);
        assertThat(refresh.getRefreshId()).isNotBlank();
    }

    @Test
    void wrongPasswordIsUnauthorized() throws Exception {
        mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "password",
                                  "username": "alice",
                                  "password": "definitely-wrong",
                                  "client_id": "cli-001",
                                  "client_secret": "secret"
                                }"""))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void wrongClientSecretIsUnauthorized() throws Exception {
        mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "password",
                                  "username": "alice",
                                  "password": "pass",
                                  "client_id": "cli-001",
                                  "client_secret": "nope"
                                }"""))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void unknownGrantTypeIsBadRequest() throws Exception {
        mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "magic",
                                  "client_id": "cli-001",
                                  "client_secret": "secret"
                                }"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    void malformedJsonIsBadRequest() throws Exception {
        mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ this is not json "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void viewerCannotRequestWriteScope() throws Exception {
        mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "password",
                                  "username": "alice",
                                  "password": "pass",
                                  "client_id": "cli-001",
                                  "client_secret": "secret",
                                  "scopes": ["payments:write"]
                                }"""))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    @Test
    void editorReceivesWriteScope() throws Exception {
        mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "password",
                                  "username": "bob",
                                  "password": "pass",
                                  "client_id": "cli-001",
                                  "client_secret": "secret",
                                  "scopes": ["payments:read", "payments:write"]
                                }"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("payments:read payments:write"));
    }

    @Test
    void clientCredentialsIssuesAccessWithoutRefresh() throws Exception {
        MvcResult result = mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "client_credentials",
                                  "client_id": "svc-001",
                                  "client_secret": "svc-secret"
                                }"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(jsonPath("$.scope").value("payments:read"))
                .andReturn();

        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        TokenClaims access = codec.decodeAndVerify(body.get("access_token").asText());
        assertThat(access.getSub()).isEqualTo("svc-001");
        assertThat(access.getScopes()).containsExactly("payments:read");
    }

    @Test
    void clientMayNotUseAGrantItIsNotRegisteredFor() throws Exception {
        mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "grant_type": "password",
                                  "username": "alice",
                                  "password": "pass",
                                  "client_id": "svc-001",
                                  "client_secret": "svc-secret"
                                }"""))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("unauthorized_client"));
    }

    @Test
    void configEndpointExposesNoSecrets() throws Exception {
        mvc.perform(get("/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(TestSecrets.ISSUER))
                .andExpect(jsonPath("$.aud").value(TestSecrets.AUDIENCE))
                .andExpect(jsonPath("$.token_alg").value("HS256"))
                .andExpect(jsonPath("$.access_ttl_sec").value(900))
                .andExpect(jsonPath("$.secret").doesNotExist());
    }
}
