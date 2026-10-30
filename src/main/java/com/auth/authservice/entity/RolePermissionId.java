package com.auth.authservice.entity;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;

@Embeddable
@Getter
@Setter
public class RolePermissionId implements Serializable {

    @Column(name = "role_id")
    private UUID roleId;

    @Column(name = "permission_id")
    private UUID permissionId;

    public RolePermissionId() {}

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof RolePermissionId other)) return false;

        return Objects.equals(roleId, other.roleId)
                && Objects.equals(permissionId, other.permissionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(roleId, permissionId);
    }
}