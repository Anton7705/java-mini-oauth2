package ru.yandex.practicum.oauth0.common.token;

public class TokenException extends RuntimeException {

    public enum Reason {
        MALFORMED("token is not a valid compact token"),
        UNSUPPORTED_ALGORITHM("unsupported signature algorithm"),
        BAD_SIGNATURE("signature verification failed"),
        WRONG_TYPE("unexpected token type"),
        ISSUER_MISMATCH("unexpected issuer"),
        AUDIENCE_MISMATCH("token is not intended for this audience"),
        NOT_YET_VALID("token is not valid yet"),
        EXPIRED("token has expired"),
        MISSING_CLAIM("required claim is missing");

        private final String defaultMessage;

        Reason(String defaultMessage) {
            this.defaultMessage = defaultMessage;
        }

        public String defaultMessage() {
            return defaultMessage;
        }
    }

    private final Reason reason;

    public TokenException(Reason reason) {
        this(reason, reason.defaultMessage());
    }

    public TokenException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
