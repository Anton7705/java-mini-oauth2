package ru.yandex.practicum.oauth0.auth.web;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import ru.yandex.practicum.oauth0.auth.config.AuthProperties;
import ru.yandex.practicum.oauth0.auth.service.TokenService;
import ru.yandex.practicum.oauth0.auth.web.dto.ConfigResponse;
import ru.yandex.practicum.oauth0.auth.web.dto.IntrospectRequest;
import ru.yandex.practicum.oauth0.auth.web.dto.IntrospectResponse;
import ru.yandex.practicum.oauth0.auth.web.dto.RevokeRequest;
import ru.yandex.practicum.oauth0.auth.web.dto.RevokeResponse;
import ru.yandex.practicum.oauth0.auth.web.dto.TokenRequest;
import ru.yandex.practicum.oauth0.auth.web.dto.TokenResponse;
import ru.yandex.practicum.oauth0.common.crypto.HmacSigner;

@RestController
public class TokenController {

    private final TokenService tokens;
    private final AuthProperties props;

    public TokenController(TokenService tokens, AuthProperties props) {
        this.tokens = tokens;
        this.props = props;
    }

    @PostMapping(path = "/token", consumes = MediaType.APPLICATION_JSON_VALUE)
    public TokenResponse token(@RequestBody TokenRequest request) {
        return tokens.issue(request);
    }

    @PostMapping(path = "/token/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
    public TokenResponse refresh(@RequestBody TokenRequest request) {
        return tokens.refresh(request);
    }

    @PostMapping(path = "/revoke", consumes = MediaType.APPLICATION_JSON_VALUE)
    public RevokeResponse revoke(@RequestBody RevokeRequest request) {
        return tokens.revoke(request);
    }

    @PostMapping(path = "/introspect", consumes = MediaType.APPLICATION_JSON_VALUE)
    public IntrospectResponse introspect(@RequestBody IntrospectRequest request) {
        return tokens.introspect(request.token());
    }

    @GetMapping("/config")
    public ConfigResponse config() {
        return new ConfigResponse(props.getIssuer(), props.getAudience(), props.getAccessTtlSec(),
                props.getRefreshTtlDays(), HmacSigner.ALGORITHM);
    }
}
