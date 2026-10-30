
package com.auth.authservice.entity;

import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "membership_application", uniqueConstraints = {
        @UniqueConstraint(name = "uk_membership_application", columnNames = { "membership_id", "application_id" }),
        @UniqueConstraint(name = "uk_membership_application_id_application", columnNames = { "id", "application_id" })
})
public class MembershipApplication {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "membership_id", nullable = false)
    private UUID membershipId;

    @Column(name = "tenant_application_id", nullable = false)
    private UUID tenantApplicationId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id", nullable = false)
    private Application application;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "membership_id", referencedColumnName = "id", insertable = false, updatable = false)
    private TenantMembership membership;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_application_id", referencedColumnName = "id", insertable = false, updatable = false)
    private TenantApplication tenantApplication;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status = Status.ACTIVE;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private OffsetDateTime createdAt;

    public enum Status {
        ACTIVE,
        SUSPENDED
    }

    @OneToMany(mappedBy = "membershipApplication", fetch = FetchType.LAZY)
    private Set<MembershipApplicationRole> membershipApplicationRoles = new HashSet<>();
}
