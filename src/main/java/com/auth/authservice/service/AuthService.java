package com.auth.authservice.service;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.LoginRequest;
import com.auth.authservice.dto.RefreshRequest;
import com.auth.authservice.dto.RegisterRequest;
import com.auth.authservice.entity.Role;
import com.auth.authservice.entity.Tenant;
import com.auth.authservice.entity.User;
import com.auth.authservice.exception.InvalidCredentialsException;
import com.auth.authservice.exception.TenantAlreadyExistsException;
import com.auth.authservice.repository.RoleRepository;
import com.auth.authservice.repository.TenantRepository;
import com.auth.authservice.repository.UserRepository;
import com.auth.authservice.security.TenantContext;

import jakarta.servlet.http.HttpServletRequest;

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

        @Transactional
        public AuthResponse register(RegisterRequest request) {

                String domain = request.getEmail().substring(request.getEmail().indexOf("@") + 1);
                if (tenantRepository.findByName(request.getTenantName()).isPresent()) {
                        throw new TenantAlreadyExistsException();
                }

                // Registration bootstraps a new tenant. Joining an existing tenant
                // must use the membership request and administrator approval flow.
                Tenant tenant = new Tenant();
                tenant.setName(request.getTenantName());
                tenant.setDomain(domain);
                tenant.setSlug(generateUniqueSlug(request.getTenantName()));

                tenantRepository.save(tenant);
                Role role = roleRepository.findByName("ADMIN")
                                .orElseThrow();

                User user = new User();
                user.setEmail(request.getEmail());
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                user.setTenantId(tenant.getId());
                user.setRoles(Set.of(role));

                userRepository.save(user);

                String accessToken = jwtService.generateToken(user);

                String refreshToken = refreshTokenService.createRefreshToken(user);

                return new AuthResponse(
                                accessToken,
                                refreshToken,
                                "Bearer",
                                expiration);
        }

        public AuthResponse login(LoginRequest request) {

                String tenantSlug = request.getTenantSlug()
                                .trim()
                                .toLowerCase(Locale.ROOT);

                Tenant tenant = tenantRepository
                                .findBySlug(tenantSlug)
                                .orElseThrow(InvalidCredentialsException::new);

                try {
                        TenantContext.set(tenant.getId());

                        authenticationManager.authenticate(
                                        new UsernamePasswordAuthenticationToken(
                                                        request.getEmail(),
                                                        request.getPassword()));

                        User user = userRepository
                                        .findByEmailAndTenantId(
                                                        request.getEmail(),
                                                        tenant.getId())
                                        .orElseThrow(InvalidCredentialsException::new);

                        String accessToken = jwtService.generateToken(user);
                        String refreshToken = refreshTokenService.createRefreshToken(user);

                        return new AuthResponse(
                                        accessToken,
                                        refreshToken,
                                        "Bearer",
                                        expiration);

                } finally {
                        TenantContext.clear();
                }
        }

        private String generateUniqueSlug(String tenantName) {

                String normalized = Normalizer.normalize(
                                tenantName.trim().toLowerCase(Locale.ROOT),
                                Normalizer.Form.NFD);

                String baseSlug = normalized
                                .replaceAll("\\p{M}", "")
                                .replaceAll("[^a-z0-9]+", "-")
                                .replaceAll("^-|-$", "");

                if (baseSlug.isBlank()) {
                        baseSlug = "tenant";
                }

                String slug = baseSlug;
                int suffix = 2;

                while (tenantRepository.findBySlug(slug).isPresent()) {
                        slug = baseSlug + "-" + suffix++;
                }

                return slug;
        }

        public AuthResponse refreshToken(RefreshRequest request) {

                RefreshTokenService.RotatedRefreshToken rotatedToken = refreshTokenService
                                .rotate(request.getRefreshToken());

                String accessToken = jwtService
                                .generateToken(rotatedToken.user());

                return new AuthResponse(
                                accessToken,
                                rotatedToken.token(),
                                "Bearer",
                                expiration);
        }

        public void logout(
                        HttpServletRequest request,
                        String email,
                        UUID tenantId,
                        RefreshRequest refreshRequest) {

                String authHeader = request.getHeader("Authorization");

                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                        throw new InvalidCredentialsException();
                }

                String accessToken = authHeader.substring(7);

                // Revoga o refresh token desta sessão
                refreshTokenService.revoke(
                                refreshRequest.getRefreshToken(),
                                email,
                                tenantId);

                // Invalida o access token atual
                long remainingTime = jwtService.getRemainingTime(accessToken);

                if (remainingTime > 0) {
                        tokenBlacklistService.blacklistToken(accessToken, remainingTime);
                }
        }

}
