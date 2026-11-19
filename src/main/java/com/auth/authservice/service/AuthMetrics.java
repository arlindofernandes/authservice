package com.auth.authservice.service;

import org.springframework.stereotype.Component;

import com.auth.authservice.repository.MembershipRequestRepository;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

@Component
public class AuthMetrics {
    private final Counter successfulLogins;
    private final Counter failedLogins;
    private final Counter refreshReuse;

    public AuthMetrics(MeterRegistry meterRegistry, MembershipRequestRepository membershipRequestRepository) {
        successfulLogins = Counter.builder("auth.logins.success").register(meterRegistry);
        failedLogins = Counter.builder("auth.logins.failed").register(meterRegistry);
        refreshReuse = Counter.builder("auth.refresh.reuse").register(meterRegistry);
        Gauge.builder("auth.membership.pending", membershipRequestRepository, repository -> repository.count())
                .description("Pending membership requests across all tenants")
                .register(meterRegistry);
    }

    public void recordSuccessfulLogin() {
        successfulLogins.increment();
    }

    public void recordFailedLogin() {
        failedLogins.increment();
    }

    public void recordRefreshReuse() {
        refreshReuse.increment();
    }
}
