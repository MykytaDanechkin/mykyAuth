package com.mykyda.mykyauth.http.filter;

import com.mykyda.mykyauth.service.AccessTokenService;
import com.mykyda.mykyauth.service.RefreshTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final AccessTokenService accessTokenService;

    private final RefreshTokenService refreshTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var cookies = request.getCookies();
        if (cookies != null) {
            String access = null;
            String refresh = null;


            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    access = cookie.getValue();
                }
                if ("refreshToken".equals(cookie.getName())) {
                    refresh = cookie.getValue();
                }
            }

            if (access != null && accessTokenService.validate(access)) {
                log.debug("successful validate access token");
            } else if (refresh != null) {
                List<Cookie> newCookies = refreshTokenService.refresh(refresh);
                if (!newCookies.isEmpty()) {
                    for (Cookie cookie : newCookies) {
                        response.addCookie(cookie);
                    }
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
