package com.auth.authservice.entity;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "membership_application_roles")
public class MembershipApplicationRole {

    @EmbeddedId
    private MembershipApplicationRoleId id;

    @Column(name = "application_id", nullable = false)
    private UUID applicationId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @MapsId("membershipApplicationId")
    @JoinColumn(
            name = "membership_application_id",
            referencedColumnName = "id"
    )
    private MembershipApplication membershipApplication;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @MapsId("roleId")
    @JoinColumn(
            name = "role_id",
            referencedColumnName = "id"
    )
    private Role role;
}