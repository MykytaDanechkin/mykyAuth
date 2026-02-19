package com.mykyda.mykyauth.service;

import com.mykyda.mykyauth.data.dto.UserCreateDTO;
import com.mykyda.mykyauth.data.entity.Role;
import com.mykyda.mykyauth.data.entity.User;
import com.mykyda.mykyauth.data.repository.UserRepository;
import com.mykyda.mykyauth.exception.AuthFailException;
import com.mykyda.mykyauth.exception.UserExistsException;
import jakarta.servlet.http.Cookie;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final AccessTokenService accessTokenService;

    private final RefreshTokenService refreshTokenService;


    @Transactional
    public void reg(UserCreateDTO userDTO) throws UserExistsException {
        var user = userRepository.findByEmail(userDTO.getEmail());
        if (user.isPresent()) {
            throw new UserExistsException("User Already Exist, register in AuthService");
        } else {
            userRepository.save(User.builder()
                    .email(userDTO.getEmail())
                    .password(passwordEncoder.encode(userDTO.getPassword()))
                    .authority(Role.USER)
                    .build());
            log.info("User {} has been registered", userDTO.getEmail());
        }
    }

    @Transactional
    public List<Cookie> login(UserCreateDTO userDTO) {
        Authentication authenticationRequest = UsernamePasswordAuthenticationToken
                .unauthenticated(userDTO.getEmail(), userDTO.getPassword());
        try {
            var authToken = authenticationManager.authenticate(authenticationRequest);
            var userId = ((User) Objects.requireNonNull(authToken.getPrincipal())).getId();

            var accessCookie = createAccessCookie(authToken, userId);

            var uuid = UUID.randomUUID();
            var refreshCookie = createRefreshCookie(userId, uuid);

            log.info("Authentication Successful with username {}", userDTO.getEmail());
            return List.of(accessCookie, refreshCookie);
        } catch (AuthenticationException e) {
            throw new AuthFailException("Incorrect credentials");
        }
    }

    private Cookie createAccessCookie(Authentication authToken, Long userId) {

        var authorities = authToken.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        var cookie = accessTokenService.createCookie(userId, authToken.getName(), authorities);
        cookie.setSecure(false);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }

    private Cookie createRefreshCookie(Long userId, UUID uuid) {
        var token = refreshTokenService.createToken(userId, uuid);
        refreshTokenService.saveToken(uuid, userId, token);
        var cookie = refreshTokenService.createCookie(token);
        cookie.setSecure(false);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }

    public List<Cookie> logout() {
        Cookie accessCookie = new Cookie("accessToken", null);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(false);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(0);

        Cookie refreshCookie = new Cookie("refreshToken", null);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(0);
        return List.of(accessCookie, refreshCookie);
    }
}