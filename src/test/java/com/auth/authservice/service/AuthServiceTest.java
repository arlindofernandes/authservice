
package com.auth.authservice.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.LoginRequest;
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

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private ApplicationRepository applicationRepository;

    @Mock
    private TenantApplicationRepository tenantApplicationRepository;

    @Mock
    private TenantMembershipRepository tenantMembershipRepository;

    @Mock
    private MembershipApplicationRepository membershipApplicationRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private AuthService authService;

    private Tenant tenant;
    private Application application;
    private User user;
    private TenantMembership membership;
    private MembershipApplication membershipApplication;

    private final String email = "user@example.com";
    private final String password = "password123";
    private final String tenantSlug = "example";
    private final String appKey = "tempora";

    @BeforeEach
    void setUp() {

        when(jwtService.getExpiration()).thenReturn(900000L);

        authService = new AuthService(
                jwtService,
                refreshTokenService,
                tokenBlacklistService,
                tenantRepository,
                applicationRepository,
                tenantApplicationRepository,
                tenantMembershipRepository,
                membershipApplicationRepository,
                passwordEncoder);

        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Example");
        tenant.setSlug(tenantSlug);
        tenant.setActive(true);

        application = new Application();
        application.setId(UUID.randomUUID());
        application.setAppKey(appKey);
        application.setName("Tempora");
        application.setActive(true);

        user = new User();
        user.setId(UUID.randomUUID());
        user.setName("Example User");
        user.setEmail(email);
        user.setPassword("encoded-password");
        user.setEnabled(true);

        membership = new TenantMembership();
        membership.setId(UUID.randomUUID());
        membership.setUser(user);
        membership.setTenant(tenant);
        membership.setStatus(TenantMembership.Status.ACTIVE);

        membershipApplication = new MembershipApplication();
        membershipApplication.setId(UUID.randomUUID());
        membershipApplication.setTenantId(tenant.getId());
        membershipApplication.setApplication(application);
        membershipApplication.setMembership(membership);
        membershipApplication.setStatus(MembershipApplication.Status.ACTIVE);
    }

    private LoginRequest validRequest() {

        LoginRequest request = new LoginRequest();
        request.setTenantSlug(tenantSlug);
        request.setAppKey(appKey);
        request.setEmail(email);
        request.setPassword(password);

        return request;
    }

    private void mockValidContext() {

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.of(tenant));

        when(applicationRepository.findByAppKeyAndActiveTrue(appKey))
                .thenReturn(Optional.of(application));

        TenantApplication tenantApplication = new TenantApplication();
        tenantApplication.setId(UUID.randomUUID());
        tenantApplication.setTenant(tenant);
        tenantApplication.setApplication(application);
        tenantApplication.setStatus(TenantApplication.Status.ACTIVE);

        when(tenantApplicationRepository.findByTenantIdAndApplicationIdAndStatus(
                tenant.getId(),
                application.getId(),
                TenantApplication.Status.ACTIVE))
                .thenReturn(Optional.of(tenantApplication));

        when(tenantMembershipRepository.findByUserEmailAndTenantSlugAndStatus(
                email,
                tenantSlug,
                TenantMembership.Status.ACTIVE))
                .thenReturn(Optional.of(membership));

        when(passwordEncoder.matches(password, user.getPassword()))
                .thenReturn(true);

        when(membershipApplicationRepository.findByMembershipIdAndApplicationIdAndStatus(
                membership.getId(),
                application.getId(),
                MembershipApplication.Status.ACTIVE))
                .thenReturn(Optional.of(membershipApplication));
    }

    @Test
    void shouldLoginSuccessfully() {

        mockValidContext();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("refresh-token");

        when(jwtService.generateToken(membershipApplication))
                .thenReturn("access-token");

        when(refreshTokenService.createRefreshToken(membershipApplication))
                .thenReturn(refreshToken);

        AuthResponse response = authService.login(validRequest());

        assertNotNull(response);
        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(900L, response.getExpiresIn());

        verify(jwtService).generateToken(membershipApplication);
        verify(refreshTokenService).createRefreshToken(membershipApplication);
    }

    @Test
    void shouldRejectLoginWhenTenantDoesNotExist() {

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.empty());

        assertThrows(
                BadCredentialsException.class,
                () -> authService.login(validRequest()));

        verify(applicationRepository, never())
                .findByAppKeyAndActiveTrue(anyString());
    }

    @Test
    void shouldRejectLoginWhenApplicationDoesNotExist() {

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.of(tenant));

        when(applicationRepository.findByAppKeyAndActiveTrue(appKey))
                .thenReturn(Optional.empty());

        assertThrows(
                BadCredentialsException.class,
                () -> authService.login(validRequest()));

        verify(tenantApplicationRepository, never())
                .findByTenantIdAndApplicationIdAndStatus(
                        any(), any(), any());
    }

    @Test
    void shouldRejectLoginWhenApplicationIsNotEnabledForTenant() {

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.of(tenant));

        when(applicationRepository.findByAppKeyAndActiveTrue(appKey))
                .thenReturn(Optional.of(application));

        when(tenantApplicationRepository.findByTenantIdAndApplicationIdAndStatus(
                tenant.getId(),
                application.getId(),
                TenantApplication.Status.ACTIVE))
                .thenReturn(Optional.empty());

        assertThrows(
                BadCredentialsException.class,
                () -> authService.login(validRequest()));

        verify(tenantMembershipRepository, never())
                .findByUserEmailAndTenantSlugAndStatus(anyString(), anyString(), any());
    }

    @Test
    void shouldRejectLoginWhenMembershipDoesNotExist() {

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.of(tenant));

        when(applicationRepository.findByAppKeyAndActiveTrue(appKey))
                .thenReturn(Optional.of(application));

        TenantApplication tenantApplication = new TenantApplication();

        when(tenantApplicationRepository.findByTenantIdAndApplicationIdAndStatus(
                tenant.getId(),
                application.getId(),
                TenantApplication.Status.ACTIVE))
                .thenReturn(Optional.of(tenantApplication));

        when(tenantMembershipRepository.findByUserEmailAndTenantSlugAndStatus(
                email,
                tenantSlug,
                TenantMembership.Status.ACTIVE))
                .thenReturn(Optional.empty());

        assertThrows(
                BadCredentialsException.class,
                () -> authService.login(validRequest()));

        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    void shouldRejectLoginWithInvalidPassword() {

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.of(tenant));

        when(applicationRepository.findByAppKeyAndActiveTrue(appKey))
                .thenReturn(Optional.of(application));

        when(tenantApplicationRepository.findByTenantIdAndApplicationIdAndStatus(
                tenant.getId(),
                application.getId(),
                TenantApplication.Status.ACTIVE))
                .thenReturn(Optional.of(new TenantApplication()));

        when(tenantMembershipRepository.findByUserEmailAndTenantSlugAndStatus(
                email,
                tenantSlug,
                TenantMembership.Status.ACTIVE))
                .thenReturn(Optional.of(membership));

        when(passwordEncoder.matches(password, user.getPassword()))
                .thenReturn(false);

        assertThrows(
                BadCredentialsException.class,
                () -> authService.login(validRequest()));

        verify(membershipApplicationRepository, never())
                .findByMembershipIdAndApplicationIdAndStatus(any(), any(), any());

        verify(refreshTokenService, never())
                .createRefreshToken(any());
    }

    @Test
    void shouldRejectLoginWhenUserIsDisabled() {

        user.setEnabled(false);

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.of(tenant));

        when(applicationRepository.findByAppKeyAndActiveTrue(appKey))
                .thenReturn(Optional.of(application));

        when(tenantApplicationRepository.findByTenantIdAndApplicationIdAndStatus(
                tenant.getId(),
                application.getId(),
                TenantApplication.Status.ACTIVE))
                .thenReturn(Optional.of(new TenantApplication()));

        when(tenantMembershipRepository.findByUserEmailAndTenantSlugAndStatus(
                email,
                tenantSlug,
                TenantMembership.Status.ACTIVE))
                .thenReturn(Optional.of(membership));

        assertThrows(
                BadCredentialsException.class,
                () -> authService.login(validRequest()));

        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(refreshTokenService, never()).createRefreshToken(any());
    }

    @Test
    void shouldRejectLoginWhenMembershipApplicationDoesNotExist() {

        when(tenantRepository.findBySlugAndActiveTrue(tenantSlug))
                .thenReturn(Optional.of(tenant));

        when(applicationRepository.findByAppKeyAndActiveTrue(appKey))
                .thenReturn(Optional.of(application));

        when(tenantApplicationRepository.findByTenantIdAndApplicationIdAndStatus(
                tenant.getId(),
                application.getId(),
                TenantApplication.Status.ACTIVE))
                .thenReturn(Optional.of(new TenantApplication()));

        when(tenantMembershipRepository.findByUserEmailAndTenantSlugAndStatus(
                email,
                tenantSlug,
                TenantMembership.Status.ACTIVE))
                .thenReturn(Optional.of(membership));

        when(passwordEncoder.matches(password, user.getPassword()))
                .thenReturn(true);

        when(membershipApplicationRepository.findByMembershipIdAndApplicationIdAndStatus(
                membership.getId(),
                application.getId(),
                MembershipApplication.Status.ACTIVE))
                .thenReturn(Optional.empty());

        assertThrows(
                BadCredentialsException.class,
                () -> authService.login(validRequest()));

        verify(refreshTokenService, never()).createRefreshToken(any());
    }
}
