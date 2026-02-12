package com.mykyda.mykyauth.http.controller;

import com.mykyda.mykyauth.data.dto.UserCreateDTO;
import com.mykyda.mykyauth.exception.UserExistsException;
import com.mykyda.mykyauth.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/login")
    public String login(@ModelAttribute UserCreateDTO userDTO, HttpServletResponse response) {
        var cookie = authService.login(userDTO);
        response.addCookie(cookie);
        return "redirect:/";
    }

    @PostMapping("/reg")
    public String reg(@ModelAttribute UserCreateDTO userDTO) throws UserExistsException {
        authService.reg(userDTO);
        return "redirect:/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        response.addCookie(authService.logout());
        SecurityContextHolder.clearContext();
        return "redirect:/login?logout";
    }
}
