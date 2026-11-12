package com.auth.authservice.config;

import java.time.Instant;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth.authservice.security.JwtAuthenticationFilter;
import com.auth.authservice.exception.ApiError;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, ObjectMapper objectMapper) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.objectMapper = objectMapper;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/register", "/auth/login", "/auth/refresh").permitAll()
                        .requestMatchers("/auth/logout").authenticated()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            writeSecurityError(request.getRequestURI(), response, HttpServletResponse.SC_UNAUTHORIZED,
                                    "Unauthorized", "Authentication is required");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            writeSecurityError(request.getRequestURI(), response, HttpServletResponse.SC_FORBIDDEN,
                                    "Forbidden", "Access is denied");
                        }))
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    private void writeSecurityError(
            String path,
            HttpServletResponse response,
            int status,
            String error,
            String message) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), new ApiError(
                Instant.now(), status, error, message, path, Map.of()));
    }

}
