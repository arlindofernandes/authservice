package com.auth.authservice.service;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.LoginRequest;
import com.auth.authservice.dto.RefreshRequest;
import com.auth.authservice.dto.RegisterRequest;
import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.entity.Role;
import com.auth.authservice.entity.Tenant;
import com.auth.authservice.entity.User;
import com.auth.authservice.repository.RoleRepository;
import com.auth.authservice.repository.TenantRepository;
import com.auth.authservice.repository.UserRepository;
import com.auth.authservice.security.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    long expiration;

    public AuthService(AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       RefreshTokenService refreshTokenService,
                       TokenBlacklistService tokenBlacklistService,
                       TenantRepository tenantRepository,
                       UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder

    ) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.tenantRepository = tenantRepository;
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;

        expiration = jwtService.getExpiration() / 1000; // Convert to seconds
    }

    public AuthResponse register(RegisterRequest request) {

        String domain = request.getEmail().substring(request.getEmail().indexOf("@") + 1);
        Tenant tenant = tenantRepository
                .findByName(request.getTenantName())
                .orElse(null);
        Role role;
        if (tenant == null) {
            //PRIMEIRO USUÁRIO É ADMIN → CRIA TENANT
            tenant = new Tenant();
            tenant.setName(request.getTenantName());
            tenant.setDomain(domain);
            tenantRepository.save(tenant);
            role = roleRepository.findByName("ADMIN")
                    .orElseThrow();
        } else {
            //VALIDAR DOMÍNIO DO EMAIL
            String emailDomain = request.getEmail().split("@")[1];

            if (!emailDomain.equalsIgnoreCase(tenant.getDomain())) {
                throw new RuntimeException("Email domain not allowed");
            }
            //USUÁRIOS POSTERIORES → USER
            role = roleRepository.findByName("USER")
                    .orElseThrow();
        }
        if (userRepository.findByEmailAndTenantId(request.getEmail(), tenant.getId()).isPresent()) {
            throw new RuntimeException("Email already registered in this tenant");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setTenantId(tenant.getId());
        user.setRoles(Set.of(role));

        userRepository.save(user);

        String accessToken = jwtService.generateToken(user);

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return new AuthResponse(
                accessToken,
                refreshToken.getToken(),
                "Bearer",
                expiration);
    }

    public AuthResponse login(LoginRequest request) {

        // extrai domínio do email
        String domain = request.getEmail()
                .substring(request.getEmail().indexOf("@") + 1);
        System.out.println(domain);
        Tenant tenant = tenantRepository
                .findByDomain(domain)
                .orElseThrow(() -> new RuntimeException("Tenant not found"));

        try {
            TenantContext.set(tenant.getId());

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()));
            User user = userRepository
                    .findByEmailAndTenantId(request.getEmail(), tenant.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));


            String accessToken = jwtService.generateToken(user);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            return new AuthResponse(
                    accessToken,
                    refreshToken.getToken(),
                    "Bearer",
                    expiration);
        } finally {
            TenantContext.clear();
        }
    }

    public AuthResponse refreshToken(RefreshRequest request) {

        // 🔥 valida + marca como usado
        RefreshToken oldToken = refreshTokenService
                .validateAndRotate(request.getRefreshToken());

        // 🔥 cria novo refresh token
        RefreshToken newToken = refreshTokenService
                .createRefreshToken(oldToken.getUser());

        // 🔥 gera novo access token
        String accessToken = jwtService
                .generateToken(oldToken.getUser());

        return new AuthResponse(
                accessToken,
                newToken.getToken(),
                "Bearer",
                expiration);
    }

    public void logout(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        String token = authHeader.substring(7);

        long remainingTime = jwtService.getRemainingTime(token);

        tokenBlacklistService.blacklistToken(token, remainingTime);
    }

}
