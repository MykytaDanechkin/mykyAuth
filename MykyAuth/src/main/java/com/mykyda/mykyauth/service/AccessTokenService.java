package com.mykyda.mykyauth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccessTokenService {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String ISSUER;

    @Value("${spring.security.jwt.access-token.secret}")
    private String SECRET_KEY;

    @Value("${spring.security.jwt.access-token.exp-min}")
    private int TOKEN_VALIDITY_MINUTES;

    @Value("${spring.security.jwt.cookie.same-site}")
    private String COOKIE_SAME_SITE;

    @Value("${spring.security.jwt.cookie.secure}")
    private String COOKIE_SECURE;

    @Value("${spring.security.jwt.cookie.http-only}")
    private String COOKIE_HTTP_ONLY;

    @Value("${spring.security.jwt.cookie.path}")
    private String COOKIE_PATH;

    public Cookie createCookie(Long id, String email, Collection<? extends GrantedAuthority> authorities) {
        var authoritiesList = authorities
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        var cookie = new Cookie("accessToken", createToken(id, email, authoritiesList));
        cookie.setSecure(Boolean.parseBoolean(COOKIE_SECURE));
        cookie.setHttpOnly(Boolean.parseBoolean(COOKIE_HTTP_ONLY));
        cookie.setPath(COOKIE_PATH);
        cookie.setAttribute("SameSite", COOKIE_SAME_SITE);
        cookie.setMaxAge(TOKEN_VALIDITY_MINUTES * 60);
        return cookie;
    }

    private String createToken(Long id, String username, List<String> roles) {
        return Jwts.builder()
                .setIssuer(ISSUER)
                .setSubject(id.toString())
                .claim("username", username)
                .claim("authorities", roles)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(60L * TOKEN_VALIDITY_MINUTES)))
                .signWith(getSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public Claims parseToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSecretKey()).build().parseClaimsJws(token).getBody();
    }

    public boolean validate(String token) {
        try {
            var parsedToken = parseToken(token);
            var username = parsedToken.get("username").toString();
            var roles = ((List<String>) parsedToken.get("authorities"))
                    .stream()
                    .map(org.springframework.security.core.authority.SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
            var auth = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    roles
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
            return true;
        } catch (Exception e) {
            log.warn("Invalid token{}", e.getMessage());
            return false;
        }
    }
}
