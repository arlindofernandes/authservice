
package com.auth.authservice.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(
    name = "tenant_membership",
    uniqueConstraints = {
        @UniqueConstraint(
            name = "uk_tenant_membership_user_tenant",
            columnNames = {"user_id", "tenant_id"}
        ),
        @UniqueConstraint(
            name = "uk_tenant_membership_id_tenant",
            columnNames = {"id", "tenant_id"}
        )
    }
)
public class TenantMembership {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status = Status.ACTIVE;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private OffsetDateTime createdAt;

    public enum Status {
        ACTIVE,
        INVITED,
        SUSPENDED
    }
}
