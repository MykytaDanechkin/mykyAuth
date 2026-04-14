package com.mykyda.mykyauth.http.controller;

import com.mykyda.mykyauth.data.dto.UserCreateDTO;
import com.mykyda.mykyauth.exception.UserExistsException;
import com.mykyda.mykyauth.service.AuthService;
import com.mykyda.mykyauth.service.RefreshTokenService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.feature.rest",
        name = "enabled",
        havingValue = "true"
)
public class AuthRestController {

    private final AuthService authService;

    private final RefreshTokenService refreshTokenService;

    @PostConstruct
    public void postConstruct() {
        log.info("REST controller was loaded");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserCreateDTO userDTO, HttpServletResponse response) {
        var cookies = authService.login(userDTO);
        for (Cookie cookie : cookies) {
            response.addCookie(cookie);
        }
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reg")
    public ResponseEntity<String>  reg(@RequestBody UserCreateDTO userDTO) throws UserExistsException {
        authService.reg(userDTO);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        if (request.getCookies() != null) {
            refreshTokenService.revokeByToken(request.getCookies());
        }
        var cookies = authService.logout();
        for (Cookie cookie : cookies) {
            response.addCookie(cookie);
        }
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/checkrest")
    public String checkrest(){
        return "nima mvc";
    }
}
