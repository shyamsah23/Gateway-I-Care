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
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

        // Bypass for login/register or preflight: still attach secret header and preserve Authorization if present
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
            // Validate token (JwtUtil should throw if invalid)
            Claims claims = jwtUtil.validateToken(jwtToken);

            // Mutate request using WebFlux ServerHttpRequest.Builder (do not consume body)
            Builder mutatedBuilder = request.mutate();

            // forward original Authorization header (important for downstream servlet services)
            mutatedBuilder.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken);

            // add your secret header
            mutatedBuilder.header(SECRET_HEADER_NAME, secretKeyForHeader);

            ServerHttpRequest modifiedRequest = mutatedBuilder.build();

            log.debug("Token validated for subject={}, forwarding request to downstream", claims.getSubject());

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        } catch (Exception e) {
            log.warn("Token validation failed for request {} {} : {}", request.getMethod(), path, e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
