package ru.yandex.practicum.oauth0.rs.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import ru.yandex.practicum.oauth0.common.api.ErrorResponse;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    private final ObjectMapper mapper;

    public AuthorizationInterceptor(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        RequiresAuthority required = method.getMethodAnnotation(RequiresAuthority.class);
        if (required == null) {
            return true;
        }

        Object attribute = request.getAttribute(TokenPrincipal.ATTRIBUTE);
        if (!(attribute instanceof TokenPrincipal principal)) {
            write(response, HttpStatus.UNAUTHORIZED, "invalid_token", "authentication is required");
            return false;
        }

        List<String> missingScopes = Arrays.stream(required.scopes())
                .filter(scope -> !principal.hasScope(scope))
                .toList();
        if (!missingScopes.isEmpty()) {
            log.info("denied {} for sub={}: missing scopes {}",
                    request.getRequestURI(), principal.subject(), missingScopes);
            write(response, HttpStatus.FORBIDDEN, "insufficient_scope",
                    "missing required scopes: " + missingScopes);
            return false;
        }

        List<String> allowedRoles = Arrays.asList(required.roles());
        if (!allowedRoles.isEmpty() && !principal.hasAnyRole(allowedRoles)) {
            log.info("denied {} for sub={}: none of the roles {} present",
                    request.getRequestURI(), principal.subject(), allowedRoles);
            write(response, HttpStatus.FORBIDDEN, "insufficient_role",
                    "one of the following roles is required: " + allowedRoles);
            return false;
        }

        return true;
    }

    private void write(HttpServletResponse response, HttpStatus status, String error, String description)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        mapper.writeValue(response.getWriter(), new ErrorResponse(error, description));
    }
}
