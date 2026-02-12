package com.mykyda.mykyauth.http.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class PageController {

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/reg")
    public String regPage() {
        return "reg";
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }
}
