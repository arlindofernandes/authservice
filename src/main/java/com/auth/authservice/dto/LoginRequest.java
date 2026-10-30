package com.auth.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {
    @NotBlank
    private String tenantSlug;

    @NotBlank
    private String appKey;

    @NotBlank
    private String email;

    @NotBlank
    private String password;

}
