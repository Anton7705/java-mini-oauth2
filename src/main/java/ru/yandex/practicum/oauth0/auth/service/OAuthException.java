package ru.yandex.practicum.oauth0.auth.service;

import org.springframework.http.HttpStatus;

public class OAuthException extends RuntimeException {

    private final HttpStatus status;
    private final String error;

    public OAuthException(HttpStatus status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    public static OAuthException badRequest(String error, String description) {
        return new OAuthException(HttpStatus.BAD_REQUEST, error, description);
    }

    public static OAuthException unauthorized(String error, String description) {
        return new OAuthException(HttpStatus.UNAUTHORIZED, error, description);
    }

    public static OAuthException forbidden(String error, String description) {
        return new OAuthException(HttpStatus.FORBIDDEN, error, description);
    }

    public static OAuthException conflict(String error, String description) {
        return new OAuthException(HttpStatus.CONFLICT, error, description);
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }
}
