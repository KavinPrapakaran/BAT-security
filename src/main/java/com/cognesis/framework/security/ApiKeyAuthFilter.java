package com.cognesis.framework.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private final Set<String> validApiKeys;

    public ApiKeyAuthFilter(Set<String> validApiKeys) {
        this.validApiKeys = validApiKeys;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String apiKey = extractApiKey(request);
        if (apiKey != null && validApiKeys.contains(apiKey)) {
            AbstractAuthenticationToken auth = new ApiKeyAuthentication(apiKey,
                    AuthorityUtils.createAuthorityList("ROLE_API"));
            auth.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }

    private String extractApiKey(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return request.getHeader("X-API-Key");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return "/actuator/health".equals(path) || "/actuator/info".equals(path);
    }

    public static class ApiKeyAuthentication extends AbstractAuthenticationToken {
        private final String apiKey;

        public ApiKeyAuthentication(String apiKey, java.util.Collection<? extends GrantedAuthority> authorities) {
            super(authorities);
            this.apiKey = apiKey;
        }

        @Override
        public Object getCredentials() {
            return apiKey;
        }

        @Override
        public Object getPrincipal() {
            return apiKey;
        }
    }
}
