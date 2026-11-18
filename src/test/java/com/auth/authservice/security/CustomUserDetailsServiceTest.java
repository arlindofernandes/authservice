package com.auth.authservice.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Proxy;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth.authservice.entity.Permission;
import com.auth.authservice.entity.Role;
import com.auth.authservice.entity.User;
import com.auth.authservice.repository.UserRepository;

class CustomUserDetailsServiceTest {

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void exposesRolesWithSpringSecurityPrefixAndPermissions() {
        UUID tenantId = UUID.randomUUID();
        TenantContext.set(tenantId);

        Permission permission = new Permission("USER_READ");
        Role role = new Role();
        role.setName("USER");
        role.setPermissions(Set.of(permission));

        User user = new User();
        user.setEmail("user@example.com");
        user.setPassword("encoded-password");
        user.setRoles(Set.of(role));

        UserRepository userRepository = (UserRepository) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] { UserRepository.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("findByEmailAndTenantId")) {
                        assertThat(args).containsExactly("user@example.com", tenantId);
                        return java.util.Optional.of(user);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });

        UserDetails details = new CustomUserDetailsService(userRepository)
                .loadUserByUsername("user@example.com");

        assertThat(details.getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .containsExactlyInAnyOrder("ROLE_USER", "USER_READ");
    }

    @Test
    void exposesThePersistedEnabledState() {
        UUID tenantId = UUID.randomUUID();
        TenantContext.set(tenantId);

        User user = new User();
        user.setEmail("disabled@example.com");
        user.setPassword("encoded-password");
        user.setEnabled(false);
        user.setRoles(Set.of());

        UserRepository userRepository = (UserRepository) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] { UserRepository.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("findByEmailAndTenantId")) {
                        return java.util.Optional.of(user);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });

        UserDetails details = new CustomUserDetailsService(userRepository)
                .loadUserByUsername("disabled@example.com");

        assertThat(details.isEnabled()).isFalse();
    }
}
