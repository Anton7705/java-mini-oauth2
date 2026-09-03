package ru.yandex.practicum.oauth0.auth;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class AuthApp {

    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthApp.class)
                .profiles("auth")
                .run(args);
    }
}
