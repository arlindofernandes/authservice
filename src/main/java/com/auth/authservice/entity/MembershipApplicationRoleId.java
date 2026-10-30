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
public class MembershipApplicationRoleId implements Serializable {

    @Column(name = "membership_application_id")
    private UUID membershipApplicationId;

    @Column(name = "role_id")
    private UUID roleId;

    public MembershipApplicationRoleId() {}

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MembershipApplicationRoleId other)) return false;

        return Objects.equals(membershipApplicationId, other.membershipApplicationId)
                && Objects.equals(roleId, other.roleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(membershipApplicationId, roleId);
    }
}