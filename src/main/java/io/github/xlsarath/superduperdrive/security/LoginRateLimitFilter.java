package io.github.xlsarath.superduperdrive.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.withDefaults;

/**
 * Throttles credential-guessing endpoints (login and account recovery) per client address,
 * complementing the per-account lockout, which cannot see attempts against unknown usernames.
 * Uses the container's remote address; behind a proxy, enable
 * {@code server.forward-headers-strategy} so that it reflects the real client.
 */
public final class LoginRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimitFilter.class);
    private static final RequestMatcher GUARDED = new OrRequestMatcher(
            withDefaults().matcher(HttpMethod.POST, "/login"),
            withDefaults().matcher(HttpMethod.POST, "/recover"));

    private final ClientRateLimiter limiter;

    public LoginRateLimitFilter(ClientRateLimiter limiter) {
        this.limiter = limiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !GUARDED.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (limiter.tryAcquire(request.getRemoteAddr())) {
            chain.doFilter(request, response);
            return;
        }
        log.warn("Throttled {} from a client over its attempt limit", request.getRequestURI());
        String target = request.getRequestURI().endsWith("/recover") ? "/recover?throttled" : "/login?throttled";
        response.setHeader("Retry-After", "300");
        response.sendRedirect(request.getContextPath() + target);
    }
}
