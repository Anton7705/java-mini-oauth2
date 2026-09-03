package ru.yandex.practicum.oauth0.rs;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import ru.yandex.practicum.oauth0.common.crypto.HmacSigner;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;
import ru.yandex.practicum.oauth0.common.token.TokenClaims;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.rs.security.TokenIntrospector;
import ru.yandex.practicum.oauth0.support.ResourceServerTest;
import ru.yandex.practicum.oauth0.support.TestSecrets;
import ru.yandex.practicum.oauth0.support.TestTokens;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ResourceServerTest
class ResourceAccessTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private TokenCodec codec;

    @Autowired
    private TimeProvider time;

    @MockitoBean
    private TokenIntrospector introspector;

    @BeforeEach
    void tokensAreActiveByDefault() {
        given(introspector.isActive(anyString())).willReturn(true);
    }

    @Test
    void readerCanListPayments() throws Exception {
        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(reader())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").exists());
    }

    @Test
    void missingTokenIsUnauthorized() throws Exception {
        mvc.perform(get("/api/payments"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void nonBearerSchemeIsUnauthorized() throws Exception {
        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void foreignSignatureIsUnauthorized() throws Exception {
        TokenCodec foreign = new TokenCodec(new HmacSigner(TestSecrets.WRONG_SECRET), mapper);
        long now = time.nowEpochSeconds();
        String forged = foreign.encode(TestTokens.access("u-300",
                List.of("payments:read", "payments:write"), List.of("admin"), now, now + 900));

        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(forged)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }

    @Test
    void expiredTokenIsUnauthorized() throws Exception {
        long now = time.nowEpochSeconds();
        String expired = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now - 7200, now - 3600));

        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(expired)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenJustPastExpiryIsStillAcceptedInsideTheClockSkew() throws Exception {
        long now = time.nowEpochSeconds();
        String justExpired = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now - 900, now - 30));

        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(justExpired)))
                .andExpect(status().isOk());
    }

    @Test
    void tokenForAnotherAudienceIsUnauthorized() throws Exception {
        long now = time.nowEpochSeconds();
        String otherApi = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), now, now + 900, "reports-api", TestSecrets.ISSUER));

        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(otherApi)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshTokenCannotBeUsedAsAccessToken() throws Exception {
        long now = time.nowEpochSeconds();
        String refreshToken = codec.encode(TestTokens.refresh("u-100", now, now + 3600));

        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(refreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void revokedTokenIsRejectedEvenThoughTheSignatureIsValid() throws Exception {
        given(introspector.isActive(anyString())).willReturn(false);

        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(reader())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }

    @Test
    void unreachableAuthServerYieldsServiceUnavailable() throws Exception {
        given(introspector.isActive(anyString()))
                .willThrow(new TokenIntrospector.IntrospectionUnavailableException("down", null));

        mvc.perform(get("/api/payments").header(HttpHeaders.AUTHORIZATION, bearer(reader())))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("temporarily_unavailable"));
    }

    @Test
    void writingWithoutWriteScopeIsForbidden() throws Exception {
        mvc.perform(post("/api/payments")
                        .header(HttpHeaders.AUTHORIZATION, bearer(reader()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"amount_minor\": 5000, \"currency\": \"RUB\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("insufficient_scope"));
    }

    @Test
    void writerCanCreateAPayment() throws Exception {
        mvc.perform(post("/api/payments")
                        .header(HttpHeaders.AUTHORIZATION, bearer(writer()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"amount_minor\": 5000, \"currency\": \"RUB\", \"description\": \"test\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.owner").value("u-200"))
                .andExpect(jsonPath("$.amount_minor").doesNotExist())
                .andExpect(jsonPath("$.amountMinor").value(5000));
    }

    @Test
    void deleteRequiresTheAdminRoleOnTopOfTheWriteScope() throws Exception {
        // editor holds payments:write but not the admin role
        mvc.perform(delete("/api/payments/pay-2").header(HttpHeaders.AUTHORIZATION, bearer(writer())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("insufficient_role"));

        mvc.perform(delete("/api/payments/pay-2").header(HttpHeaders.AUTHORIZATION, bearer(admin())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deleted").value("pay-2"));
    }

    // ------------------------------------------------------------------ tools

    private String bearer(String token) {
        return "Bearer " + token;
    }

    private String reader() {
        return sign(TestTokens.access("u-100", List.of("payments:read"), List.of("viewer"),
                time.nowEpochSeconds(), time.nowEpochSeconds() + 900));
    }

    private String writer() {
        return sign(TestTokens.access("u-200", List.of("payments:read", "payments:write"),
                List.of("editor"), time.nowEpochSeconds(), time.nowEpochSeconds() + 900));
    }

    private String admin() {
        return sign(TestTokens.access("u-300", List.of("payments:read", "payments:write"),
                List.of("admin"), time.nowEpochSeconds(), time.nowEpochSeconds() + 900));
    }

    private String sign(TokenClaims claims) {
        return codec.encode(claims);
    }
}
