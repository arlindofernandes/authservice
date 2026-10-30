
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
    name = "tenant_application",
    uniqueConstraints = {
        @UniqueConstraint(
            name = "uk_tenant_application",
            columnNames = {"tenant_id", "application_id"}
        ),
        @UniqueConstraint(
            name = "uk_tenant_application_id_tenant",
            columnNames = {"id", "tenant_id"}
        ),
        @UniqueConstraint(
            name = "uk_tenant_application_id_application",
            columnNames = {"id", "application_id"}
        )
    }
)
public class TenantApplication {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id", nullable = false)
    private Application application;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status = Status.ACTIVE;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private OffsetDateTime createdAt;

    public enum Status {
        ACTIVE,
        SUSPENDED
    }
}
