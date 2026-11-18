package com.auth.authservice.service;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.authservice.dto.MembershipRequestCreateRequest;
import com.auth.authservice.dto.MembershipRequestResponse;
import com.auth.authservice.entity.MembershipRequest;
import com.auth.authservice.entity.Role;
import com.auth.authservice.entity.Tenant;
import com.auth.authservice.entity.User;
import com.auth.authservice.exception.EmailAlreadyRegisteredException;
import com.auth.authservice.exception.InvalidCredentialsException;
import com.auth.authservice.exception.MembershipRequestAlreadyExistsException;
import com.auth.authservice.exception.MembershipRequestNotFoundException;
import com.auth.authservice.repository.MembershipRequestRepository;
import com.auth.authservice.repository.RoleRepository;
import com.auth.authservice.repository.TenantRepository;
import com.auth.authservice.repository.UserRepository;

@Service
public class MembershipRequestService {
    private final MembershipRequestRepository membershipRequestRepository;
    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public MembershipRequestService(MembershipRequestRepository membershipRequestRepository,
            TenantRepository tenantRepository, UserRepository userRepository,
            RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.membershipRequestRepository = membershipRequestRepository;
        this.tenantRepository = tenantRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public MembershipRequestResponse requestMembership(MembershipRequestCreateRequest request) {
        Tenant tenant = tenantRepository.findBySlug(request.getTenantSlug().trim().toLowerCase(Locale.ROOT))
                .orElseThrow(InvalidCredentialsException::new);
        if (userRepository.findByEmailAndTenantId(request.getEmail(), tenant.getId()).isPresent()) {
            throw new EmailAlreadyRegisteredException();
        }
        if (membershipRequestRepository.existsByEmailAndTenantId(request.getEmail(), tenant.getId())) {
            throw new MembershipRequestAlreadyExistsException();
        }

        MembershipRequest membershipRequest = new MembershipRequest();
        membershipRequest.setTenantId(tenant.getId());
        membershipRequest.setEmail(request.getEmail());
        membershipRequest.setPassword(passwordEncoder.encode(request.getPassword()));
        membershipRequest.setRequestedAt(Instant.now());
        return toResponse(membershipRequestRepository.save(membershipRequest));
    }

    @Transactional(readOnly = true)
    public List<MembershipRequestResponse> listForTenant(UUID tenantId) {
        return membershipRequestRepository.findAllByTenantIdOrderByRequestedAtAsc(tenantId).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public void approve(UUID requestId, UUID tenantId) {
        MembershipRequest membershipRequest = membershipRequestRepository.findByIdAndTenantId(requestId, tenantId)
                .orElseThrow(MembershipRequestNotFoundException::new);
        if (userRepository.findByEmailAndTenantId(membershipRequest.getEmail(), tenantId).isPresent()) {
            throw new EmailAlreadyRegisteredException();
        }

        Role userRole = roleRepository.findByName("USER").orElseThrow();
        User user = new User();
        user.setEmail(membershipRequest.getEmail());
        user.setPassword(membershipRequest.getPassword());
        user.setTenantId(tenantId);
        user.setRoles(Set.of(userRole));
        userRepository.save(user);
        membershipRequestRepository.delete(membershipRequest);
    }

    private MembershipRequestResponse toResponse(MembershipRequest membershipRequest) {
        return new MembershipRequestResponse(membershipRequest.getId(), membershipRequest.getEmail(),
                membershipRequest.getRequestedAt());
    }
}
