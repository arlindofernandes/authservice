package com.auth.authservice.service;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.LoginRequest;
import com.auth.authservice.dto.RefreshRequest;
import com.auth.authservice.dto.RegisterRequest;
import com.auth.authservice.entity.Role;
import com.auth.authservice.entity.Tenant;
import com.auth.authservice.entity.User;
import com.auth.authservice.exception.DomainNotAllowedException;
import com.auth.authservice.exception.EmailAlreadyRegisteredException;
import com.auth.authservice.exception.InvalidCredentialsException;
import com.auth.authservice.repository.RoleRepository;
import com.auth.authservice.repository.TenantRepository;
import com.auth.authservice.repository.UserRepository;
import com.auth.authservice.security.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    @Transactional
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
                throw new DomainNotAllowedException();
            }
            //USUÁRIOS POSTERIORES → USER
            role = roleRepository.findByName("USER")
                    .orElseThrow();
        }
        if (userRepository.findByEmailAndTenantId(request.getEmail(), tenant.getId()).isPresent()) {
            throw new EmailAlreadyRegisteredException();
        }

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

        // extrai domínio do email
        String domain = request.getEmail()
                .substring(request.getEmail().indexOf("@") + 1);
        Tenant tenant = tenantRepository
                .findByDomain(domain)
                .orElseThrow(InvalidCredentialsException::new);

        try {
            TenantContext.set(tenant.getId());

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()));
            User user = userRepository
                    .findByEmailAndTenantId(request.getEmail(), tenant.getId())
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
