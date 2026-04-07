package com.auth.authservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/api/user")
    @PreAuthorize("hasRole('USER')")
    public String user() {
        return "Acesso user";
    }

    @GetMapping("/api/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin() {
        return "Acesso admin";
    }
}