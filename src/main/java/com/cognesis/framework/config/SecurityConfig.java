package com.cognesis.framework.security;

import com.cognesis.framework.config.CognesisProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
            CognesisProperties props,
            ApiKeyAuthFilter apiKeyFilter,
            RateLimitFilter rateLimitFilter) throws Exception {

        Set<String> keys = Arrays.stream(props.getSecurity().getApiKeys().split(","))
                .map(String::trim)
                .filter(k -> !k.isEmpty())
                .collect(Collectors.toUnmodifiableSet());

        if (keys.isEmpty()) {
            log.warn("""
                    No API keys configured (cognesis.security.api-keys). \
                    All /api/v1/** and /actuator/** endpoints are LOCKED. \
                    Set COGNESIS_SECURITY_API_KEYS (comma-separated) to unlock.""");
        }

        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/actuator/**").authenticated()
                .requestMatchers("/api/v1/**").authenticated()
                .anyRequest().permitAll()
            )
            .addFilterBefore(apiKeyFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .httpBasic(b -> b.disable())
            .formLogin(f -> f.disable());

        return http.build();
    }

    @Bean
    public ApiKeyAuthFilter apiKeyAuthFilter(CognesisProperties props) {
        Set<String> keys = Arrays.stream(props.getSecurity().getApiKeys().split(","))
                .map(String::trim)
                .filter(k -> !k.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
        return new ApiKeyAuthFilter(keys);
    }

    @Bean
    public RateLimitFilter rateLimitFilter(CognesisProperties props) {
        return new RateLimitFilter(
                props.getSecurity().isRateLimitEnabled(),
                props.getSecurity().getRateLimitPerMinute());
    }
}
