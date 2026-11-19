package com.auth.authservice.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.authservice.service.JwtService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "Token verification", description = "Public keys used to verify access tokens")
public class JwksController {
    private final JwtService jwtService;

    public JwksController(JwtService jwtService) { this.jwtService = jwtService; }

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "Get the JSON Web Key Set used to verify access tokens")
    public Map<String, Object> jwks() { return jwtService.getJwkSet(); }
}
