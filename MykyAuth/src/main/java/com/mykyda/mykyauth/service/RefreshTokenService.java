package com.mykyda.mykyauth.service;

import com.mykyda.mykyauth.data.entity.RefreshToken;
import com.mykyda.mykyauth.data.entity.User;
import com.mykyda.mykyauth.data.repository.RefreshTokenRepository;
import com.mykyda.mykyauth.exception.DatabaseException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.EntityManager;
import jakarta.servlet.http.Cookie;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String ISSUER;

    @Value("${spring.security.jwt.refresh-token.secret}")
    private String SECRET_KEY;

    @Value("${spring.security.jwt.refresh-token.exp-min}")
    private int TOKEN_VALIDITY_DAYS;

    private final RefreshTokenRepository refreshTokenRepository;

    private final EntityManager entityManager;

    public Cookie createCookie(String token) {
        return new Cookie("refreshToken", token);
    }

    public String createToken(Long userId, UUID refreshTokenId) {
        return Jwts.builder()
                .setSubject(userId.toString())
                .setIssuer(ISSUER)
                .claim("token_id", refreshTokenId)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(3600L * 24L * TOKEN_VALIDITY_DAYS)))
                .signWith(getSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public Claims parseToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSecretKey()).build().parseClaimsJws(token).getBody();
    }

    @Transactional
    public void saveToken(UUID tokenId,Long userId, String token) {
        var parsedToken = parseToken(token);
        try {
            refreshTokenRepository.save(RefreshToken.builder()
                            .id(tokenId)
                            .user(entityManager.getReference(User.class, userId))
                            .tokenHash(hashToken(token))
                            .createdAt(parsedToken.getIssuedAt())
                            .expiresAt(parsedToken.getExpiration())
                            .revoked(false)
                    .build());
        } catch (Exception e){
            throw new DatabaseException(e.getMessage());
        }
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

}

