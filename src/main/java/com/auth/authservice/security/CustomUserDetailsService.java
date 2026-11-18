package com.auth.authservice.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.authservice.entity.User;
import com.auth.authservice.repository.UserRepository;

import java.util.UUID;
import java.util.stream.Stream;

@Service
public class CustomUserDetailsService implements UserDetailsService {
        private final UserRepository userRepository;

        public CustomUserDetailsService(UserRepository userRepository) {
                this.userRepository = userRepository;
        }

        @Override
        public UserDetails loadUserByUsername(String email)
                        throws UsernameNotFoundException {

                UUID tenantId = TenantContext.require();
                User user = userRepository
                                .findByEmailAndTenantId(email,tenantId)
                                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

                return org.springframework.security.core.userdetails.User
                                .builder()
                                .username(user.getEmail())
                                .password(user.getPassword())
                                .disabled(!user.isEnabled())
                                .authorities(
                                                Stream.concat(
                                                                user.getRoles().stream()
                                                                                .map(role -> new SimpleGrantedAuthority(
                                                                                                "ROLE_" + role.getName())),
                                                                user.getRoles().stream()
                                                                .flatMap(role -> role.getPermissions().stream())
                                                                .map(permission -> new SimpleGrantedAuthority(
                                                                                permission.getName())))
                                                                .distinct()
                                                                .toList())
                                .build();
        }
}
