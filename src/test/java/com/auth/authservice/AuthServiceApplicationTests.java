
package com.auth.authservice;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;

import com.auth.authservice.config.JwtProperties;
import com.auth.authservice.dto.ClientTokenResponse;
import com.auth.authservice.entity.*;
import com.auth.authservice.service.ApplicationClientService;
import com.auth.authservice.service.JwtService;

@SpringBootTest
@AutoConfigureMockMvc
class AuthServiceApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JwtService jwtService;

	@Autowired
	private JwtProperties jwtProperties;

	@MockBean
	private ApplicationClientService applicationClientService;

	private String userToken;
	private String clientToken;

	@BeforeEach
	void setUp() {
		Application application = new Application();
		application.setId(UUID.randomUUID());
		application.setAppKey("test-app");
		application.setName("Test Application");
		application.setActive(true);

		User user = new User();
		user.setId(UUID.randomUUID());
		user.setName("Test User");
		user.setEmail("test@example.com");

		Tenant tenant = new Tenant();
		tenant.setId(UUID.randomUUID());
		tenant.setName("Test Tenant");
		tenant.setSlug("test-tenant");

		TenantMembership membership = new TenantMembership();
		membership.setUser(user);
		membership.setTenant(tenant);

		Permission permission = new Permission();
		permission.setId(UUID.randomUUID());
		permission.setName("USER_READ");
		permission.setApplication(application);

		Role role = new Role();
		role.setId(UUID.randomUUID());
		role.setName("USER");
		role.setApplication(application);

		RolePermission rolePermission = new RolePermission();
		RolePermissionId rolePermissionId = new RolePermissionId();
		rolePermissionId.setRoleId(role.getId());
		rolePermissionId.setPermissionId(permission.getId());

		rolePermission.setId(rolePermissionId);
		rolePermission.setRole(role);
		rolePermission.setPermission(permission);

		role.setRolePermissions(Set.of(rolePermission));

		MembershipApplication membershipApplication = new MembershipApplication();

		membershipApplication.setId(UUID.randomUUID());
		membershipApplication.setMembership(membership);
		membershipApplication.setApplication(application);

		MembershipApplicationRole membershipRole = new MembershipApplicationRole();

		MembershipApplicationRoleId membershipRoleId = new MembershipApplicationRoleId();

		membershipRoleId.setMembershipApplicationId(
				membershipApplication.getId());
		membershipRoleId.setRoleId(role.getId());

		membershipRole.setId(membershipRoleId);
		membershipRole.setMembershipApplication(membershipApplication);
		membershipRole.setRole(role);

		membershipApplication.setMembershipApplicationRoles(
				new HashSet<>(Set.of(membershipRole)));

		ApplicationClient client = new ApplicationClient();
		client.setClientId("test-client");
		client.setApplication(application);
		client.setName("Test Client");
		client.setActive(true);

		UUID sessionId = UUID.randomUUID();
		userToken = jwtService.generateToken(membershipApplication, sessionId);
		clientToken = jwtService.generateClientToken(client);
	}

	@Test
	void contextLoads() {
	}

	@Test
	void shouldReturnClientTokenWhenCredentialsAreValid() throws Exception {
		when(applicationClientService.issueToken("test-client", "secret"))
				.thenReturn(new ClientTokenResponse(
						"fake-jwt-token", "Bearer", 300));

		mockMvc.perform(post("/auth/client-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{
						    "clientId": "test-client",
						    "clientSecret": "secret"
						}
						"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.accessToken").value("fake-jwt-token"))
				.andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andExpect(jsonPath("$.expiresIn").value(300));
	}

	@Test
	void shouldReturnUnauthorizedWhenCredentialsAreInvalid() throws Exception {
		when(applicationClientService.issueToken("test-client", "wrong-secret"))
				.thenThrow(new BadCredentialsException("Invalid credentials"));

		mockMvc.perform(post("/auth/client-token")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{
						    "clientId": "test-client",
						    "clientSecret": "wrong-secret"
						}
						"""))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.message").value("Invalid credentials"));
	}

	@Test
	void shouldRejectInternalRequestWithoutToken() throws Exception {
		mockMvc.perform(get("/internal/test"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void shouldRejectUserTokenOnInternalEndpoint() throws Exception {
		assertTrue(
				jwtService.isClientTokenValid(clientToken),
				"O JWT de aplicação deveria ser válido antes da requisição");

		mockMvc.perform(get("/internal/test")
				.header("Authorization", "Bearer " + userToken))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void shouldAllowClientTokenOnInternalEndpoint() throws Exception {
		mockMvc.perform(get("/internal/test")
				.header("Authorization", "Bearer " + clientToken))
				.andExpect(status().isOk())
				.andExpect(content().string("Acesso application client"));
	}

	@Test
	void shouldRejectClientTokenOnUserEndpoint() throws Exception {
		mockMvc.perform(get("/api/user")
				.header("Authorization", "Bearer " + clientToken))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void shouldRejectLogoutWithoutToken() throws Exception {
		mockMvc.perform(post("/auth/logout"))
				.andExpect(status().isUnauthorized());
	}
}
