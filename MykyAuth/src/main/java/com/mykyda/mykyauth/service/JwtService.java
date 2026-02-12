package com.mykyda.mykyauth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String ISSUER;

    @Value("${spring.security.jwt.secret}")
    private String SECRET_KEY;

    @Value("${spring.security.jwt.exp-min}")
    private int TOKEN_VALIDITY_MINUTES;

    public String createToken(String username, List<String> roles) {
        return Jwts.builder()
                .setIssuer(ISSUER)
                .setSubject(username)
                .claim("username", username)
                .claim("authorities", roles)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(60L * TOKEN_VALIDITY_MINUTES)))
                .signWith(getSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public Claims parseToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSecretKey()).build().parseClaimsJws(token).getBody();
    }

    public Cookie createCookie(String email, List<String> authorities) {
        return new Cookie("accessToken", createToken(email, authorities));
    }
}
