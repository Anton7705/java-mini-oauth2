package ru.yandex.practicum.oauth0.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import ru.yandex.practicum.oauth0.common.codec.Base64Url;
import ru.yandex.practicum.oauth0.common.crypto.HmacSigner;
import ru.yandex.practicum.oauth0.common.crypto.PasswordHasher;
import ru.yandex.practicum.oauth0.common.token.TokenClaims;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.common.token.TokenException;
import ru.yandex.practicum.oauth0.common.token.TokenKind;
import ru.yandex.practicum.oauth0.common.token.TokenValidator;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenCodecTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final TokenCodec codec = new TokenCodec(new HmacSigner(TestSecrets.SECRET), mapper);
    private final TokenValidator validator = new TokenValidator();

    @Test
    void encodesAndVerifiesRoundTrip() {
        TokenClaims claims = TestTokens.access("u-100", List.of("payments:read"), List.of("viewer"),
                1_000L, 1_900L);

        String token = codec.encode(claims);
        TokenClaims decoded = codec.decodeAndVerify(token);

        assertThat(token.split("\\.")).hasSize(3);
        assertThat(decoded.getSub()).isEqualTo("u-100");
        assertThat(decoded.getScopes()).containsExactly("payments:read");
        assertThat(decoded.getRoles()).containsExactly("viewer");
        assertThat(decoded.getTyp()).isEqualTo(TokenKind.ACCESS);
    }

    @Test
    void rejectsTokenSignedWithAnotherSecret() {
        TokenCodec foreign = new TokenCodec(new HmacSigner(TestSecrets.WRONG_SECRET), mapper);
        String token = foreign.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), 1_000L, 1_900L));

        assertThatThrownBy(() -> codec.decodeAndVerify(token))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).getReason())
                .isEqualTo(TokenException.Reason.BAD_SIGNATURE);
    }

    @Test
    void rejectsTamperedPayload() {
        String token = codec.encode(TestTokens.access("u-100", List.of("payments:read"),
                List.of("viewer"), 1_000L, 1_900L));
        String[] parts = token.split("\\.");
        String tampered = parts[0] + "."
                + Base64Url.encode(Base64Url.decodeToString(parts[1]).replace("payments:read", "payments:write"))
                + "." + parts[2];

        assertThatThrownBy(() -> codec.decodeAndVerify(tampered))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).getReason())
                .isEqualTo(TokenException.Reason.BAD_SIGNATURE);
    }

    @Test
    void rejectsAlgorithmNone() {
        String header = Base64Url.encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = Base64Url.encode("{\"typ\":\"AT\",\"sub\":\"u-100\",\"iat\":1,\"exp\":9999999999}");

        assertThatThrownBy(() -> codec.decodeAndVerify(header + "." + payload + "."))
                .isInstanceOf(TokenException.class);
    }

    @Test
    void rejectsMalformedToken() {
        assertThatThrownBy(() -> codec.decodeAndVerify("not-a-token"))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).getReason())
                .isEqualTo(TokenException.Reason.MALFORMED);
    }

    @Test
    void lifetimeHonoursClockSkewOnBothEnds() {
        TokenClaims claims = TestTokens.access("u-100", List.of("payments:read"), List.of("viewer"),
                1_000L, 1_900L);

        // 30 seconds before iat, inside a 60 second skew
        validator.validateLifetime(claims, 970L, 60L);
        // 30 seconds past exp, inside the skew
        validator.validateLifetime(claims, 1_930L, 60L);

        assertThatThrownBy(() -> validator.validateLifetime(claims, 800L, 60L))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).getReason())
                .isEqualTo(TokenException.Reason.NOT_YET_VALID);

        assertThatThrownBy(() -> validator.validateLifetime(claims, 2_100L, 60L))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).getReason())
                .isEqualTo(TokenException.Reason.EXPIRED);
    }

    @Test
    void audienceAndTypeAreChecked() {
        TokenClaims claims = TestTokens.access("u-100", List.of("payments:read"), List.of("viewer"),
                1_000L, 1_900L, "other-api", TestSecrets.ISSUER);

        assertThatThrownBy(() -> validator.validateAudience(claims, TestSecrets.AUDIENCE))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).getReason())
                .isEqualTo(TokenException.Reason.AUDIENCE_MISMATCH);

        assertThatThrownBy(() -> validator.validateType(claims, TokenKind.REFRESH))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).getReason())
                .isEqualTo(TokenException.Reason.WRONG_TYPE);
    }

    @Test
    void bcryptHashesAreSaltedAndVerifiable() {
        PasswordHasher hasher = new PasswordHasher(4);

        String first = hasher.hash("mySecret123");
        String second = hasher.hash("mySecret123");

        assertThat(first).isNotEqualTo(second);
        assertThat(hasher.matches("mySecret123", first)).isTrue();
        assertThat(hasher.matches("wrongPass", first)).isFalse();
        assertThat(hasher.matches("mySecret123", "not-a-bcrypt-hash")).isFalse();
    }
}
