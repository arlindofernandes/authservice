package com.auth.authservice.config;

import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.auth.authservice.entity.Permission;
import com.auth.authservice.entity.Role;
import com.auth.authservice.repository.PermissionRepository;
import com.auth.authservice.repository.RoleRepository;

@Profile("dev")
@Component
public class DataInitializer implements CommandLineRunner {

        private final RoleRepository roleRepository;
        private final PermissionRepository permissionRepository;

        public DataInitializer(RoleRepository roleRepository,
                        PermissionRepository permissionRepository) {
                this.roleRepository = roleRepository;
                this.permissionRepository = permissionRepository;
        }

        @Override
        public void run(String... args) {

                // 🔐 Permissions
                Permission userRead = createPermissionIfNotExists("USER_READ");
                Permission userWrite = createPermissionIfNotExists("USER_WRITE");
                Permission userDelete = createPermissionIfNotExists("USER_DELETE");

                // 👤 Role USER
                createOrUpdateRole("USER", Set.of(userRead));

                // 👑 Role ADMIN
                createOrUpdateRole("ADMIN", Set.of(userRead, userWrite, userDelete));
        }

        private Permission createPermissionIfNotExists(String name) {
                return permissionRepository.findByName(name)
                                .orElseGet(() -> permissionRepository.save(new Permission(name)));
        }

        private void createOrUpdateRole(String name, Set<Permission> permissions) {
                Role role = roleRepository.findByName(name)
                                .orElseGet(() -> {
                                        Role newRole = new Role();
                                        newRole.setName(name);
                                        return newRole;
                                });

                role.setPermissions(permissions); // 🔥 SEMPRE atualiza

                roleRepository.save(role);
        }
}
