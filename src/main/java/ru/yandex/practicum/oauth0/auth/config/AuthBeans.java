package ru.yandex.practicum.oauth0.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.yandex.practicum.oauth0.common.crypto.HmacSigner;
import ru.yandex.practicum.oauth0.common.crypto.PasswordHasher;
import ru.yandex.practicum.oauth0.common.time.SystemTimeProvider;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.common.token.TokenValidator;

@Configuration
public class AuthBeans {

    @Bean
    public HmacSigner hmacSigner(AuthProperties properties) {
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
    public PasswordHasher passwordHasher() {
        return new PasswordHasher();
    }

    @Bean
    public TimeProvider timeProvider() {
        return new SystemTimeProvider();
    }
}
