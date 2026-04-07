package com.auth.authservice.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.authservice.entity.User;
import com.auth.authservice.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {
        private final UserRepository userRepository;

        public CustomUserDetailsService(UserRepository userRepository) {
                this.userRepository = userRepository;
        }

        @Override
        public UserDetails loadUserByUsername(String email)
                        throws UsernameNotFoundException {

                User user = userRepository
                                .findByEmail(email)
                                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

                return org.springframework.security.core.userdetails.User
                                .builder()
                                .username(user.getEmail())
                                .password(user.getPassword())
                                .authorities(
                                                user.getRoles()
                                                                .stream()
                                                                .flatMap(role -> role.getPermissions().stream())
                                                                .map(permission -> new SimpleGrantedAuthority(
                                                                                permission.getName()))
                                                                .toList())
                                .build();
        }
}
