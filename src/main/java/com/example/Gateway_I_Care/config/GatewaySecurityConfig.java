package com.example.Gateway_I_Care.config;

import com.example.Gateway_I_Care.Security.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;

@Component
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,JwtAuthFilter jwtAuthFilter) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)   // correct modern way
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers(
                                "/auth/**"
                        ).permitAll()
                        .pathMatchers(
                                "/profile/**",
                                "/pharmacy/**",
                                "/media/**",
                                "/appointment/**",
                                "/api/mail/**"
                        ).authenticated()
                        .anyExchange().denyAll()
                ).addFilterAt(jwtAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }

}
