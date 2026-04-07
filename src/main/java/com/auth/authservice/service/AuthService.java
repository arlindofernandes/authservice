package com.auth.authservice.service;

import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.authservice.dto.AuthResponse;
import com.auth.authservice.dto.LoginRequest;
import com.auth.authservice.dto.RefreshRequest;
import com.auth.authservice.dto.RegisterRequest;
import com.auth.authservice.entity.RefreshToken;
import com.auth.authservice.entity.Role;
import com.auth.authservice.entity.User;
import com.auth.authservice.repository.RoleRepository;
import com.auth.authservice.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class AuthService {

        private final AuthenticationManager authenticationManager;
        private final JwtService jwtService;
        private final RefreshTokenService refreshTokenService;
        private final TokenBlacklistService tokenBlacklistService;
        private final UserRepository userRepository;
        private final RoleRepository roleRepository;
        private final PasswordEncoder passwordEncoder;
        long expiration;

        public AuthService(AuthenticationManager authenticationManager,
                        JwtService jwtService,
                        RefreshTokenService refreshTokenService,
                        TokenBlacklistService tokenBlacklistService,
                        UserRepository userRepository,
                        RoleRepository roleRepository,
                        PasswordEncoder passwordEncoder

        ) {
                this.authenticationManager = authenticationManager;
                this.jwtService = jwtService;
                this.refreshTokenService = refreshTokenService;
                this.tokenBlacklistService = tokenBlacklistService;
                this.userRepository = userRepository;
                this.roleRepository = roleRepository;
                this.passwordEncoder = passwordEncoder;

                expiration = jwtService.getExpiration() / 1000; // Convert to seconds
        }

        public AuthResponse register(RegisterRequest request) {

                if (userRepository.findByEmail(request.getEmail()).isPresent()) {
                        throw new RuntimeException("Email already registered");
                }

                User user = new User();
                user.setEmail(request.getEmail());
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                Role userRole = roleRepository
                                .findByName("USER")
                                .orElseThrow();

                user.setRoles(Set.of(userRole));

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
                authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                request.getEmail(),
                                                request.getPassword()));

                User user = userRepository
                                .findByEmail(request.getEmail())
                                .orElseThrow(() -> new RuntimeException("User not found"));

                String accessToken = jwtService.generateToken(user);

                RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

                return new AuthResponse(
                                accessToken,
                                refreshToken.getToken(),
                                "Bearer",
                                expiration);
        }

        public AuthResponse refreshToken(RefreshRequest request) {

                User user = refreshTokenService.validateRefreshToken(
                                request.getRefreshToken());

                String accessToken = jwtService.generateToken(user);

                return new AuthResponse(
                                accessToken,
                                request.getRefreshToken(),
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
