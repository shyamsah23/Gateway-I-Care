package com.example.Gateway_I_Care.Security;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest.Builder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${secret.header.key}")
    private String secretKeyForHeader;

    private static final String SECRET_HEADER_NAME = "X-SECRET-KEY";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath() == null ? "" : request.getURI().getPath().toLowerCase();
        boolean isOptions = HttpMethod.OPTIONS.equals(request.getMethod());
        boolean isLoginOrRegister = path.contains("/auth/user/login") || path.contains("/auth/user/register");

        // Bypass for login/register or preflight:still attach secret header and preserve Authorization if present
        if (isLoginOrRegister || isOptions) {
            Builder bypassBuilder = request.mutate();
            bypassBuilder.header(SECRET_HEADER_NAME, secretKeyForHeader);

            String existingAuth = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (existingAuth != null) {
                bypassBuilder.header(HttpHeaders.AUTHORIZATION, existingAuth);
            }

            ServerHttpRequest mutated = bypassBuilder.build();
            log.debug("Bypass auth for {} {}, forwarded {} and preserved Authorization={}",
                    request.getMethod(), path, SECRET_HEADER_NAME, existingAuth != null);
            return chain.filter(exchange.mutate().request(mutated).build());
        }

        // For other endpoints require Authorization header
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for {} {}", request.getMethod(), path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String jwtToken = authHeader.substring(7); // token without "Bearer "

        try {
            // Validate token
            Claims claims = jwtUtil.validateToken(jwtToken);

            // Build Authentication object
            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            List<GrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_" + role));

            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);

            // Mutate request
            Builder mutatedBuilder = request.mutate();
            mutatedBuilder.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken);
            mutatedBuilder.header(SECRET_HEADER_NAME, secretKeyForHeader);

            ServerHttpRequest modifiedRequest = mutatedBuilder.build();

            log.debug("Token validated for subject={}, role={}", username, role);

            return chain.filter(exchange.mutate().request(modifiedRequest).build())
                    .contextWrite(
                            ReactiveSecurityContextHolder.withAuthentication(authentication)
                    );

        } catch (Exception e) {
            log.warn("Token validation failed for request {} {} : {}", request.getMethod(), path, e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
