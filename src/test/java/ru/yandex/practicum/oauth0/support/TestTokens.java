package ru.yandex.practicum.oauth0.support;

import ru.yandex.practicum.oauth0.common.token.TokenClaims;
import ru.yandex.practicum.oauth0.common.token.TokenKind;

import java.util.List;
import java.util.UUID;

public final class TestTokens {

    private TestTokens() {
    }

    public static TokenClaims access(String subject, List<String> scopes, List<String> roles,
                                     long iat, long exp) {
        return access(subject, scopes, roles, iat, exp, TestSecrets.AUDIENCE, TestSecrets.ISSUER);
    }

    public static TokenClaims access(String subject, List<String> scopes, List<String> roles,
                                     long iat, long exp, String audience, String issuer) {
        TokenClaims claims = new TokenClaims();
        claims.setTyp(TokenKind.ACCESS);
        claims.setIss(issuer);
        claims.setAud(audience);
        claims.setSub(subject);
        claims.setClientId("cli-001");
        claims.setScopes(scopes);
        claims.setRoles(roles);
        claims.setIat(iat);
        claims.setExp(exp);
        claims.setJti(UUID.randomUUID().toString());
        return claims;
    }

    public static TokenClaims refresh(String subject, long iat, long exp) {
        TokenClaims claims = new TokenClaims();
        claims.setTyp(TokenKind.REFRESH);
        claims.setIss(TestSecrets.ISSUER);
        claims.setAud(TestSecrets.ISSUER);
        claims.setSub(subject);
        claims.setClientId("cli-001");
        claims.setScopes(List.of("payments:read"));
        claims.setIat(iat);
        claims.setExp(exp);
        claims.setJti(UUID.randomUUID().toString());
        claims.setRefreshId(UUID.randomUUID().toString());
        return claims;
    }
}
