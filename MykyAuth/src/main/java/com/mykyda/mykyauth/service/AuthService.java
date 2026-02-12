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

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

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
    public Cookie login(UserCreateDTO userDTO) {
        Authentication authenticationRequest = UsernamePasswordAuthenticationToken
                .unauthenticated(userDTO.getEmail(), userDTO.getPassword());
        try {
            var authToken = authenticationManager.authenticate(authenticationRequest);
            var authorities = authToken.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            var cookie = jwtService.createCookie(authToken.getName(), authorities);
            cookie.setSecure(false);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setAttribute("SameSite", "Lax");
            log.info("Authentication Successful with username {}", userDTO.getEmail());
            return cookie;
        } catch (AuthenticationException e) {
            throw new AuthFailException("Incorrect credentials");
        }
    }

    public Cookie logout() {
        Cookie cookie = new Cookie("accessToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }
}