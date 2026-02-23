package com.mykyda.mykyauth.service;

import com.mykyda.mykyauth.data.entity.RefreshToken;
import com.mykyda.mykyauth.data.entity.User;
import com.mykyda.mykyauth.data.repository.RefreshTokenRepository;
import com.mykyda.mykyauth.exception.DatabaseException;
import com.mykyda.mykyauth.util.EmptyCookiesUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.EntityManager;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String ISSUER;

    @Value("${spring.security.jwt.refresh-token.secret}")
    private String SECRET_KEY;

    @Value("${spring.security.jwt.refresh-token.exp-days}")
    private int TOKEN_VALIDITY_DAYS;

    @Value("${spring.security.jwt.cookie.same-site}")
    private String COOKIE_SAME_SITE;

    @Value("${spring.security.jwt.cookie.secure}")
    private String COOKIE_SECURE;

    @Value("${spring.security.jwt.cookie.http-only}")
    private String COOKIE_HTTP_ONLY;

    @Value("${spring.security.jwt.cookie.path}")
    private String COOKIE_PATH;

    private final RefreshTokenRepository refreshTokenRepository;

    private final EntityManager entityManager;

    private final AccessTokenService accessTokenService;

    public Cookie createCookie(String token) {
        var cookie = new Cookie("refreshToken", token);
        cookie.setSecure(Boolean.parseBoolean(COOKIE_SECURE));
        cookie.setHttpOnly(Boolean.parseBoolean(COOKIE_HTTP_ONLY));
        cookie.setPath(COOKIE_PATH);
        cookie.setAttribute("SameSite", COOKIE_SAME_SITE);
        cookie.setMaxAge(TOKEN_VALIDITY_DAYS *  24 * 60 * 60);
        return cookie;
    }

    public String createToken(Long userId, UUID refreshTokenId) {
        return Jwts.builder()
                .setSubject(userId.toString())
                .setIssuer(ISSUER)
                .setId(refreshTokenId.toString())
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(3600L * 24L * TOKEN_VALIDITY_DAYS)))
                .signWith(getSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public Claims parseToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSecretKey()).build().parseClaimsJws(token).getBody();
    }

    @Transactional
    public void saveToken(UUID tokenId, Long userId, String token) {
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
        } catch (Exception e) {
            throw new DatabaseException(e.getMessage());
        }
    }

    public String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Transactional(readOnly = true)
    public RefreshToken getById(UUID id) {
        try {
            return refreshTokenRepository.findById(id).orElse(null);
        } catch (Exception e) {
            throw new DatabaseException(e.getMessage());
        }
    }

    @Transactional
    public List<Cookie> refresh(String token) {
        try {
            var claims = parseToken(token);
            var tokenId = UUID.fromString(claims.getId());
            var refreshEntity = getById(tokenId);

            if (refreshEntity == null) return Collections.emptyList();

            var userId = refreshEntity.getUser().getId();
            var username = refreshEntity.getUser().getUsername();
            var authorities = refreshEntity.getUser().getAuthorities();

            if (refreshEntity.isRevoked()) {
                log.warn("usage of revoked refresh token");
                return suspiciousRevoke(userId);
            }
            if (!claims.getSubject()
                    .equals(refreshEntity.getUser().getId().toString())) {
                log.warn("suspicious refresh token");
                return suspiciousRevoke(userId);
            }
            if (!refreshEntity.getTokenHash()
                    .equals(hashToken(token))) {
                log.warn("suspicious refresh token");
                return suspiciousRevoke(userId);
            }

            return new ArrayList<>(rotateRefreshToken(userId, tokenId, username, authorities));
        } catch (ExpiredJwtException e) {
            log.warn("refresh token expired");
            var claims = e.getClaims();
            return revokeOneOrAllReuse(claims);
        } catch (Exception e) {
            log.warn("Invalid refresh token {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    @Transactional
    public List<Cookie> suspiciousRevoke(Long userId) {
        revokeAllByUserId(userId);
        SecurityContextHolder.clearContext();
        return EmptyCookiesUtil.getEmptyCookies();
    }

    private Cookie createNewAccessCookie(Long userId, String username,
                                         Collection<? extends GrantedAuthority> authorities) {
        var newAccessCookie =
                accessTokenService.createCookie(
                        userId,
                        username,
                        authorities
                );
        var auth = new UsernamePasswordAuthenticationToken(
                username,
                null,
                authorities
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        return newAccessCookie;
    }

    @Transactional
    public List<Cookie> rotateRefreshToken(Long userId,
                                           UUID tokenId,
                                           String username,
                                           Collection<? extends GrantedAuthority> authorities) {
        int updated = setRevoke(tokenId);
        if (updated == 0) {
            log.warn("reuse detected during rotation");
            return suspiciousRevoke(userId);
        }
        var uuid = UUID.randomUUID();
        var token = createToken(userId, uuid);
        saveToken(uuid, userId, token);
        var newAccessCookie = createNewAccessCookie(userId, username, authorities);
        return List.of(newAccessCookie, createCookie(token));
    }

    @Transactional
    public int setRevoke(UUID id) {
        try {
            return refreshTokenRepository.revoke(id);
        } catch (Exception e) {
            throw new DatabaseException(e.getMessage());
        }
    }

    @Transactional
    public void revokeAllByUserId(Long userId) {
        try {
            refreshTokenRepository.revokeAllByUserId(userId);
        } catch (Exception e) {
            throw new DatabaseException(e.getMessage());
        }
    }

    @Transactional
    public void revokeByToken(Cookie[] cookies) {
        try {
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals("refreshToken")) {
                        var claims = parseToken(cookie.getValue());
                        revokeOneOrAllReuse(claims);
                        return;
                    }
                }
            }
        } catch (ExpiredJwtException e) {
            var claims = e.getClaims();
            revokeOneOrAllReuse(claims);
        }
    }

    @Transactional
    public List<Cookie> revokeOneOrAllReuse(Claims claims) {
        try {
            int updated = setRevoke(UUID.fromString(claims.getId()));
            if (updated == 0) {
                log.warn("suspicious reuse of refresh token");
                return suspiciousRevoke(Long.parseLong(claims.getSubject()));
            }
            return EmptyCookiesUtil.getEmptyCookies();
        } catch (Exception e) {
            return EmptyCookiesUtil.getEmptyCookies();
        }
    }
}

