package com.example.Gateway_I_Care.Security;

import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

import java.util.List;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthFilter implements WebFilter {

    Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${secret.header.key}")
    private String secretKeyForHeader;

    private static final String SECRET_HEADER_NAME = "X-Secret-key";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath().toLowerCase();
        log.info("Path is = {}", path);
        boolean isOptions = HttpMethod.OPTIONS.equals(request.getMethod());
        boolean isPublic = path.contains("/auth/user/login") || path.contains("/auth/user/register");

        // bypass for login / register / options
        if (isOptions || isPublic) {
            return chain.filter(
                    exchange.mutate()
                            .request(request.mutate().header(SECRET_HEADER_NAME, secretKeyForHeader).build())
                            .build()
            );
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("AuthHeader is = {}", authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        log.info("Token = {}", token);

        try {
            Claims claims = jwtUtil.validateToken(token);

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(SECRET_HEADER_NAME, secretKeyForHeader)
                    .build();
            log.info("Claims is = {}", claims);
            log.info("Modified request ={}", modifiedRequest);
            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
