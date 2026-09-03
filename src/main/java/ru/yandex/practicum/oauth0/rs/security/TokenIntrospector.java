package ru.yandex.practicum.oauth0.rs.security;

public interface TokenIntrospector {

    class IntrospectionUnavailableException extends RuntimeException {
        public IntrospectionUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    boolean isActive(String token);
}
