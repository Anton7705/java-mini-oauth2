package ru.yandex.practicum.oauth0.support;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import ru.yandex.practicum.oauth0.auth.AuthApp;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(classes = AuthApp.class, properties = {
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.url=jdbc:h2:mem:mini-oauth2-auth-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "auth.secret=" + TestSecrets.SECRET,
        "auth.issuer=" + TestSecrets.ISSUER,
        "auth.audience=" + TestSecrets.AUDIENCE,
        "auth.access-ttl-sec=900",
        "auth.refresh-ttl-days=14",
        "auth.clock-skew-sec=60",
        "auth.seed-demo-data=true",
        "auth.rate-limit.enabled=false"
})
@AutoConfigureMockMvc
public @interface AuthServerTest {
}
