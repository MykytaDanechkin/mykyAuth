package com.mykyda.mykyauth.handler;

import com.mykyda.mykyauth.data.dto.UserCreateDTO;
import com.mykyda.mykyauth.data.entity.RegistrationType;
import com.mykyda.mykyauth.data.entity.Role;
import com.mykyda.mykyauth.data.entity.User;
import com.mykyda.mykyauth.data.repository.UserRepository;
import com.mykyda.mykyauth.service.AccessTokenService;
import com.mykyda.mykyauth.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class OauthSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;

    private final AccessTokenService accessTokenService;

    private final RefreshTokenService refreshTokenService;

    private final OAuth2AuthorizedClientService authorizedClientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        var user = (OAuth2User) authentication.getPrincipal();
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        String provider = token.getAuthorizedClientRegistrationId();
        var email = "";
        RegistrationType registrationType = RegistrationType.UNDEFINED;
        switch (provider) {
            case "google" -> {
                email = Objects.requireNonNull(user).getAttribute("email");
                registrationType = RegistrationType.GOOGLE;
            }
            case "github" -> {
                Objects.requireNonNull(user).getAttribute("login");
                registrationType = RegistrationType.GITHUB;
                email = getGithubEmail(token);
            }
            default -> Objects.requireNonNull(user).getAttribute("email");
        }
        //TODO: WHAT IF USER HAD REGISTERED BEFORE BUT WITH DEFAULT

        var optUser = userRepository.findByEmail(email).orElse(null);
        Long userId;
        if (optUser == null) {
            var userDTO = new UserCreateDTO(email, null);
            userId = reg(userDTO, registrationType);
        } else {
            if (!optUser.getRegistrationType().equals(registrationType)) {
                handleResponse(response);
                return;
                //TODO: CHANGE IN CASE OF OAUTH SUB IMPLEMENTATION
            }
            userId = optUser.getId();
        }

        setCookies(response, authentication, userId);
    }

    private @Nullable String getGithubEmail(OAuth2AuthenticationToken token) {
        WebClient webClient = WebClient.builder()
                .baseUrl("https://api.github.com")
                .build();

        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient(
                        token.getAuthorizedClientRegistrationId(),
                        token.getName()
                );

        List<Map<String, Object>> emails = webClient.get()
                .uri("/user/emails")
                .headers(headers -> headers.setBearerAuth(client.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(List.class)
                .block();
        if (emails != null) {
            return emails.getFirst().get("email").toString();
        } else {
            return null;
        }
    }

    private static void handleResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("Different kind of login is used for this account");
        response.sendRedirect("/login?error=oauth_conflict");
    }

    private void setCookies(HttpServletResponse response, Authentication authentication, Long userId) {
        var accessCookie = createAccessCookie(authentication, userId);
        var uuid = UUID.randomUUID();
        refreshTokenService.revokeAllByUserId(userId);
        var refreshCookie = createRefreshCookie(userId, uuid);
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
    }

    private Cookie createAccessCookie(Authentication authToken, Long userId) {
        return accessTokenService.createCookie(userId, authToken.getName(), authToken.getAuthorities());
    }

    private Cookie createRefreshCookie(Long userId, UUID uuid) {
        var token = refreshTokenService.createToken(userId, uuid);
        refreshTokenService.saveToken(uuid, userId, token);
        return refreshTokenService.createCookie(token);
    }

    private Long reg(UserCreateDTO userDTO, RegistrationType registrationType) {
        var savedUser = userRepository.save(User.builder()
                .email(userDTO.getEmail())
                .authority(Role.USER)
                .registrationType(registrationType)
                .build());
        log.info("User {} have been registered", userDTO.getEmail());
        return savedUser.getId();
    }
}
