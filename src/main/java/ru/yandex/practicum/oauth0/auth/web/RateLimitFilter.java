package ru.yandex.practicum.oauth0.auth.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.yandex.practicum.oauth0.auth.config.AuthProperties;
import ru.yandex.practicum.oauth0.common.api.ErrorResponse;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final AuthProperties props;
    private final TimeProvider time;
    private final ObjectMapper mapper;

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    private record Window(long minute, AtomicInteger count) {
    }

    public RateLimitFilter(AuthProperties props, TimeProvider time, ObjectMapper mapper) {
        this.props = props;
        this.time = time;
        this.mapper = mapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!props.getRateLimit().isEnabled()) {
            return true;
        }
        String path = request.getRequestURI();
        return !path.startsWith("/token");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String key = request.getRemoteAddr();
        long minute = time.nowEpochSeconds() / 60;

        Window window = windows.compute(key, (k, existing) ->
                existing == null || existing.minute() != minute
                        ? new Window(minute, new AtomicInteger(0))
                        : existing);

        if (window.count().incrementAndGet() > props.getRateLimit().getRequestsPerMinute()) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            response.setHeader("Retry-After", "60");
            mapper.writeValue(response.getWriter(),
                    new ErrorResponse("rate_limited", "too many token requests, try again later"));
            return;
        }

        chain.doFilter(request, response);
    }
}
