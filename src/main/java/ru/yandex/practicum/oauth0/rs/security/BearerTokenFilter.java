package ru.yandex.practicum.oauth0.rs.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.yandex.practicum.oauth0.common.api.ErrorResponse;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;
import ru.yandex.practicum.oauth0.common.token.TokenClaims;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.common.token.TokenException;
import ru.yandex.practicum.oauth0.common.token.TokenKind;
import ru.yandex.practicum.oauth0.common.token.TokenValidator;
import ru.yandex.practicum.oauth0.rs.config.RsProperties;

import java.io.IOException;
import java.util.LinkedHashSet;

@Component
public class BearerTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenCodec codec;
    private final TokenValidator validator;
    private final TokenIntrospector introspector;
    private final TimeProvider time;
    private final RsProperties props;
    private final ObjectMapper mapper;

    public BearerTokenFilter(TokenCodec codec, TokenValidator validator, TokenIntrospector introspector,
                             TimeProvider time, RsProperties props, ObjectMapper mapper) {
        this.codec = codec;
        this.validator = validator;
        this.introspector = introspector;
        this.time = time;
        this.props = props;
        this.mapper = mapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            unauthorized(response, "invalid_request", "Authorization: Bearer <access_token> is required");
            return;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();

        TokenClaims claims;
        try {
            claims = codec.decodeAndVerify(token);
            validator.validate(claims, TokenKind.ACCESS, props.getIssuer(), props.getAudience(),
                    time.nowEpochSeconds(), props.getClockSkewSec());
        } catch (TokenException e) {
            log.info("rejected access token: {} ({})", e.getReason(), e.getMessage());
            unauthorized(response, "invalid_token", e.getMessage());
            return;
        }

        if (props.isIntrospectionEnabled()) {
            try {
                if (!introspector.isActive(token)) {
                    log.info("rejected access token jti={}: not active at the authorization server",
                            claims.getJti());
                    unauthorized(response, "invalid_token", "token is no longer active");
                    return;
                }
            } catch (TokenIntrospector.IntrospectionUnavailableException e) {
                writeError(response, HttpStatus.SERVICE_UNAVAILABLE, "temporarily_unavailable",
                        "unable to verify the token with the authorization server");
                return;
            }
        }

        TokenPrincipal principal = new TokenPrincipal(
                claims.getSub(),
                claims.getClientId(),
                new LinkedHashSet<>(claims.getScopes()),
                new LinkedHashSet<>(claims.getRoles()),
                claims.getJti(),
                claims.getExp());
        request.setAttribute(TokenPrincipal.ATTRIBUTE, principal);

        chain.doFilter(request, response);
    }

    private void unauthorized(HttpServletResponse response, String error, String description)
            throws IOException {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"" + error + "\"");
        writeError(response, HttpStatus.UNAUTHORIZED, error, description);
    }

    private void writeError(HttpServletResponse response, HttpStatus status, String error,
                            String description) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        mapper.writeValue(response.getWriter(), new ErrorResponse(error, description));
    }
}
