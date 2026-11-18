package com.auth.authservice.dto;

import java.time.Instant;
import java.util.UUID;

public record MembershipRequestResponse(UUID id, String email, Instant requestedAt) {
}
