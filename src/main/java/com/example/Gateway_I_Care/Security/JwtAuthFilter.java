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
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE) // runs before security
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

        if (isLoginOrRegister || isOptions) {
            ServerHttpRequest mutated = request.mutate()
                    .header(SECRET_HEADER_NAME, secretKeyForHeader)
                    .build();
            log.debug("Bypass auth for {} {}, forwarded with {}",
                    request.getMethod(), path, SECRET_HEADER_NAME);
            return chain.filter(exchange.mutate().request(mutated).build());
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String jwtToken = authHeader.substring(7);
        try {
            Claims claims = jwtUtil.validateToken(jwtToken);
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-USER-ID", claims.get("userId").toString())
                    .header("X-USERNAME", claims.getSubject())
                    .header(SECRET_HEADER_NAME, secretKeyForHeader)
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
