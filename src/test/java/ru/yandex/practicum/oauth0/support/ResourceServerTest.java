package ru.yandex.practicum.oauth0.support;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import ru.yandex.practicum.oauth0.rs.ResourceApp;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(classes = ResourceApp.class, properties = {
        "rs.secret=" + TestSecrets.SECRET,
        "rs.issuer=" + TestSecrets.ISSUER,
        "rs.audience=" + TestSecrets.AUDIENCE,
        "rs.clock-skew-sec=60",
        "rs.introspection-enabled=true"
})
@AutoConfigureMockMvc
public @interface ResourceServerTest {
}
