package com.auth.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.RolePermission;
import com.auth.authservice.entity.RolePermissionId;

public interface RolePermissionRepository
        extends JpaRepository<RolePermission, RolePermissionId> {
}