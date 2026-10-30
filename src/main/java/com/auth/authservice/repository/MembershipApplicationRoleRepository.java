package com.auth.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authservice.entity.MembershipApplicationRole;
import com.auth.authservice.entity.MembershipApplicationRoleId;

public interface MembershipApplicationRoleRepository
        extends JpaRepository<MembershipApplicationRole, MembershipApplicationRoleId> {
}