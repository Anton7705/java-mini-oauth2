package ru.yandex.practicum.oauth0.common.token;

public class TokenValidator {

    public void validateType(TokenClaims claims, String expectedType) {
        if (!expectedType.equals(claims.getTyp())) {
            throw new TokenException(TokenException.Reason.WRONG_TYPE,
                    "expected typ=" + expectedType + ", got " + claims.getTyp());
        }
    }

    public void validateIssuer(TokenClaims claims, String expectedIssuer) {
        if (expectedIssuer != null && !expectedIssuer.equals(claims.getIss())) {
            throw new TokenException(TokenException.Reason.ISSUER_MISMATCH,
                    "expected iss=" + expectedIssuer + ", got " + claims.getIss());
        }
    }

    public void validateAudience(TokenClaims claims, String expectedAudience) {
        if (expectedAudience != null && !expectedAudience.equals(claims.getAud())) {
            throw new TokenException(TokenException.Reason.AUDIENCE_MISMATCH,
                    "expected aud=" + expectedAudience + ", got " + claims.getAud());
        }
    }

    public void validateLifetime(TokenClaims claims, long nowEpochSeconds, long clockSkewSeconds) {
        if (nowEpochSeconds < claims.getIat() - clockSkewSeconds) {
            throw new TokenException(TokenException.Reason.NOT_YET_VALID);
        }
        if (nowEpochSeconds > claims.getExp() + clockSkewSeconds) {
            throw new TokenException(TokenException.Reason.EXPIRED);
        }
    }

    public void validate(TokenClaims claims, String expectedType, String expectedIssuer,
                         String expectedAudience, long nowEpochSeconds, long clockSkewSeconds) {
        validateType(claims, expectedType);
        validateIssuer(claims, expectedIssuer);
        validateAudience(claims, expectedAudience);
        validateLifetime(claims, nowEpochSeconds, clockSkewSeconds);
    }
}
