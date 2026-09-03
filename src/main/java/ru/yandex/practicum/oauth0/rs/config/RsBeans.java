package ru.yandex.practicum.oauth0.rs.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.yandex.practicum.oauth0.common.crypto.HmacSigner;
import ru.yandex.practicum.oauth0.common.time.SystemTimeProvider;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.common.token.TokenValidator;
import ru.yandex.practicum.oauth0.rs.security.RemoteTokenIntrospector;
import ru.yandex.practicum.oauth0.rs.security.TokenIntrospector;

@Configuration
public class RsBeans {

    @Bean
    public HmacSigner hmacSigner(RsProperties properties) {
        return new HmacSigner(properties.getSecret());
    }

    @Bean
    public TokenCodec tokenCodec(HmacSigner signer, ObjectMapper mapper) {
        return new TokenCodec(signer, mapper);
    }

    @Bean
    public TokenValidator tokenValidator() {
        return new TokenValidator();
    }

    @Bean
    public TimeProvider timeProvider() {
        return new SystemTimeProvider();
    }

    @Bean
    public TokenIntrospector tokenIntrospector(RsProperties properties) {
        return new RemoteTokenIntrospector(properties.getAuthServerUrl());
    }
}
