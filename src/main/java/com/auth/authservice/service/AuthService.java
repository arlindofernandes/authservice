package com.auth.authservice.service;

import java.util.Locale;
import java.util.UUID;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.LoginRequest;
import com.auth.authservice.dto.RefreshRequest;
import com.auth.authservice.entity.Application;
import com.auth.authservice.entity.MembershipApplication;
import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.entity.Tenant;
import com.auth.authservice.entity.TenantApplication;
import com.auth.authservice.entity.TenantMembership;
import com.auth.authservice.entity.User;
import com.auth.authservice.repository.ApplicationRepository;
import com.auth.authservice.repository.MembershipApplicationRepository;
import com.auth.authservice.repository.TenantApplicationRepository;
import com.auth.authservice.repository.TenantMembershipRepository;
import com.auth.authservice.repository.TenantRepository;
import com.auth.authservice.security.AuthPrincipal;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class AuthService {

        private final JwtService jwtService;
        private final RefreshTokenService refreshTokenService;
        private final TokenBlacklistService tokenBlacklistService;

        private final TenantRepository tenantRepository;
        private final ApplicationRepository applicationRepository;
        private final TenantApplicationRepository tenantApplicationRepository;
        private final TenantMembershipRepository tenantMembershipRepository;
        private final MembershipApplicationRepository membershipApplicationRepository;

        private final PasswordEncoder passwordEncoder;

        private final long expiration;

        public AuthService(
                        JwtService jwtService,
                        RefreshTokenService refreshTokenService,
                        TokenBlacklistService tokenBlacklistService,
                        TenantRepository tenantRepository,
                        ApplicationRepository applicationRepository,
                        TenantApplicationRepository tenantApplicationRepository,
                        TenantMembershipRepository tenantMembershipRepository,
                        MembershipApplicationRepository membershipApplicationRepository,
                        PasswordEncoder passwordEncoder) {

                this.jwtService = jwtService;
                this.refreshTokenService = refreshTokenService;
                this.tokenBlacklistService = tokenBlacklistService;
                this.tenantRepository = tenantRepository;
                this.applicationRepository = applicationRepository;
                this.tenantApplicationRepository = tenantApplicationRepository;
                this.tenantMembershipRepository = tenantMembershipRepository;
                this.membershipApplicationRepository = membershipApplicationRepository;
                this.passwordEncoder = passwordEncoder;

                this.expiration = jwtService.getExpiration() / 1000;
        }

        @Transactional
        public AuthResponse login(LoginRequest request) {

                String email = request.getEmail()
                                .trim()
                                .toLowerCase(Locale.ROOT);

                // 1. Localiza o tenant.
                Tenant tenant = tenantRepository
                                .findBySlugAndActiveTrue(request.getTenantSlug())
                                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

                // 2. Localiza a aplicação.
                Application application = applicationRepository
                                .findByAppKeyAndActiveTrue(request.getAppKey())
                                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

                // 3. Verifica se a aplicação está habilitada para o tenant.
                tenantApplicationRepository
                                .findByTenantIdAndApplicationIdAndStatus(
                                                tenant.getId(),
                                                application.getId(),
                                                TenantApplication.Status.ACTIVE)
                                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

                // 4. Localiza a associação do usuário com o tenant.
                TenantMembership membership = tenantMembershipRepository
                                .findByUserEmailAndTenantSlugAndStatus(
                                                email,
                                                tenant.getSlug(),
                                                TenantMembership.Status.ACTIVE)
                                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

                User user = membership.getUser();

                // 5. Verifica usuário e senha.
                if (!user.isEnabled()
                                || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                        throw new BadCredentialsException("Invalid credentials");
                }

                // 6. Verifica se o usuário possui acesso à aplicação.
                MembershipApplication membershipApplication = membershipApplicationRepository
                                .findByMembershipIdAndApplicationIdAndStatus(
                                                membership.getId(),
                                                application.getId(),
                                                MembershipApplication.Status.ACTIVE)
                                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

                // 7. Cria uma nova sessão.
                UUID sessionId = UUID.randomUUID();

                // Emite os tokens vinculados à mesma sessão.
                String accessToken = jwtService.generateToken(
                                membershipApplication,
                                sessionId);

                RefreshToken refreshToken = refreshTokenService
                                .createRefreshToken(membershipApplication, sessionId);

                return new AuthResponse(
                                accessToken,
                                refreshToken.getToken(),
                                "Bearer",
                                expiration);
        }

        @Transactional
        public AuthResponse refreshToken(RefreshRequest request) {

                // Valida e invalida o refresh token anterior.
                RefreshToken oldToken = refreshTokenService
                                .validateAndRotate(request.getRefreshToken());

                MembershipApplication membershipApplication = oldToken.getMembershipApplication();

                // Confere se o acesso continua ativo.
                validateMembershipApplication(membershipApplication);

                // Recupera o identificador da sessão anterior.
                UUID sessionId = oldToken.getSessionId();

                // Emite novos tokens preservando a sessão.
                String accessToken = jwtService.generateToken(
                                membershipApplication,
                                sessionId);

                RefreshToken newToken = refreshTokenService
                                .createRefreshToken(membershipApplication, sessionId);

                return new AuthResponse(
                                accessToken,
                                newToken.getToken(),
                                "Bearer",
                                expiration);
        }

        private void validateMembershipApplication(
                        MembershipApplication membershipApplication) {

                if (membershipApplication.getStatus() != MembershipApplication.Status.ACTIVE
                                || membershipApplication.getMembership().getStatus() != TenantMembership.Status.ACTIVE
                                || membershipApplication.getTenantApplication()
                                                .getStatus() != TenantApplication.Status.ACTIVE
                                || !membershipApplication.getMembership().getTenant().isActive()
                                || !membershipApplication.getApplication().isActive()
                                || !membershipApplication.getMembership().getUser().isEnabled()) {

                        throw new BadCredentialsException("Invalid refresh token");
                }
        }

        public void logout(HttpServletRequest request, AuthPrincipal principal) {

                String authHeader = request.getHeader("Authorization");

                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                        throw new BadCredentialsException("Invalid authentication");
                }

                String token = authHeader.substring(7);

                long remainingTime = jwtService.getRemainingTime(token);

                // Revoga os refresh tokens somente da sessão atual.
                refreshTokenService.revokeSession(principal.sessionId());

                // Invalida o access token utilizado nesta requisição.
                tokenBlacklistService.blacklistToken(token, remainingTime);
        }
}