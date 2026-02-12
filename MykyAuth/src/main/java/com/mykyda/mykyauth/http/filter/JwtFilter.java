package com.mykyda.mykyauth.http.filter;

import com.mykyda.mykyauth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        SecurityContextHolder.clearContext();
        var cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    validate(cookie.getValue());
                    break;
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    private void validate(String token) {
        try {
            var parsedToken = jwtService.parseToken(token);
            if (parsedToken.getExpiration().before(new Date())) {
                log.warn("Token expired");
                return;
            }
            var username = parsedToken.getSubject();
            var roles = Stream.of(parsedToken.get("authorities"))
                    .map(String::valueOf)
                    .map(org.springframework.security.core.authority.SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
            var auth = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    roles
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (Exception e) {
            log.warn("Invalid token{}", e.getMessage());
        }
    }
}
