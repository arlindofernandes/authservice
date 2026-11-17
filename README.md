# 🔐 Auth Service

Authentication and Authorization Service built with **Spring Boot**, designed for secure and scalable SaaS applications.

Implements JWT authentication, Role-Based Access Control (RBAC), refresh token rotation with reuse detection, and multi-tenant architecture.

---

## ⭐ Highlights

- Multi-tenant architecture (SaaS-ready)
- Tenant-based authentication using a unique tenant slug
- Refresh token rotation with reuse detection
- Redis-based access token blacklist
- Tenant-scoped user registration and authentication

---

## 🚀 Tech Stack

- Java 21
- Spring Boot
- Spring Security
- JWT (JJWT)
- PostgreSQL
- Redis
- Flyway (database migrations)
- Docker & Docker Compose
- JUnit 5
- Testcontainers

---

## 📌 Features

- ✅ User registration
- ✅ JWT authentication
- ✅ Refresh token rotation and reuse detection
- ✅ Role-Based Access Control (RBAC)
- ✅ Permission management
- ✅ Logout with token revocation and Redis blacklist
- ✅ Protected endpoints
- ✅ Database versioning with Flyway
- ✅ Multi-tenant architecture
- ✅ Tenant-scoped email uniqueness
- ✅ Support for different email domains within the same tenant
- ✅ Tenant identification using a unique slug
- ✅ Integration tests with PostgreSQL and Redis using Testcontainers

---

## 🏗️ Architecture

The project follows a layered architecture, separating HTTP handling, business logic, data access, and security responsibilities.

### System Architecture

```mermaid
flowchart TD
    Client["Client / Frontend"]

    subgraph AuthService["Auth Service - Spring Boot"]
        Security["Spring Security"]
        Filter["JWT Authentication Filter"]
        Controller["Controllers"]
        Service["Services"]
        Repository["Repositories"]
        TenantContext["TenantContext"]

        Client --> Security
        Security --> Filter
        Filter --> TenantContext
        Filter --> Controller
        Controller --> Service
        Service --> Repository
    end

    Repository --> PostgreSQL[("PostgreSQL")]
    Service --> Redis[("Redis")]

    PostgreSQL --- Data["Users / Tenants / Roles / Permissions / Refresh Tokens"]
    Redis --- Blacklist["Access Token Blacklist"]
```

### Application Layers

- **Controller** → handles HTTP requests
- **Service** → implements business logic
- **Repository** → manages data access
- **Security** → JWT, filters, and authentication logic
- **DTO** → request and response models
- **Config** → application configuration
- **Entity** → JPA domain entities

---

## 🧩 Multi-Tenant Design

This project implements a shared database and shared schema architecture.

```text
Shared Database + Shared Schema + tenant_id
```

### Key Concepts

- Each user belongs to a **tenant**.
- Each tenant has a unique **slug** used during authentication.
- Users are identified by their email within their tenant.
- The same email address can exist in different tenants.
- Users within the same tenant can have different email domains.
- `tenant_id` is included in the JWT claims.
- `TenantContext` (ThreadLocal) propagates the current tenant context during request processing.
- Tenant isolation is enforced through tenant-aware authentication and data access.

### Example

```text
Tenant: Acme
Slug: acme

admin@acme.com  → Tenant: Acme (ADMIN)
user@gmail.com  → Tenant: Acme (USER)
```

Both users belong to the same tenant, even though their email domains are different.

---

## 🔐 Authentication Flow

The authentication process supports automatic tenant creation and tenant-based login.

### Registration and Login

```mermaid
flowchart TD
    A["User Registration"] --> B["Provide tenantName, email and password"]
    B --> C{"Does tenant exist?"}

    C -->|No| D["Create Tenant"]
    D --> E["Assign ADMIN role"]

    C -->|Yes| F["Assign USER role"]

    E --> G["Create User"]
    F --> G

    G --> H["Generate Access and Refresh Tokens"]

    I["User Login"] --> J["Provide tenantSlug, email and password"]
    J --> K["Find Tenant by Slug"]
    K --> L["Validate User Credentials"]
    L --> M["Generate JWT with tenantId"]
    M --> N["Authenticated Requests"]
```

### Authentication Rules

1. User registers by providing an email, password, and tenant name.
2. If the tenant does not exist, it is created automatically.
3. The first user becomes **ADMIN**.
4. Subsequent users registering under the same tenant become **USER**.
5. The tenant is identified during login using its unique slug.
6. JWT tokens include the user's `tenantId`.
7. Authenticated requests use the JWT to establish the tenant context and validate access.

---

## 🔄 Token Flow

The service uses short-lived access tokens and refresh tokens to maintain authenticated sessions.

### Token Lifecycle

```mermaid
flowchart TD
    A["Login"] --> B["Access Token + Refresh Token"]

    B --> C["Access Token"]
    C --> D["Authenticated API Requests"]

    B --> E["Refresh Token"]
    E --> F["Refresh Request"]

    F --> G{"Refresh Token Valid?"}

    G -->|No| H["Reject Request"]
    G -->|Yes| I["Revoke Current Refresh Token"]

    I --> J["Generate New Token Pair"]
    J --> K["Return New Access and Refresh Tokens"]

    I --> L["Previous Refresh Token Invalidated"]
```

Refresh token reuse detection prevents previously rotated tokens from being reused.

---

## 🔒 Security

- Passwords hashed with BCrypt.
- JWT signed with a secret key.
- Token expiration enforced.
- Refresh token rotation with reuse detection.
- Refresh tokens stored as SHA-256 hashes.
- Role- and permission-based authorization.
- Access token blacklist using Redis.
- Stateless HTTP security configuration.
- Tenant-aware authentication and isolation.

---

## ⚙️ Running the Project

### Requirements

- Java 21
- Docker
- Docker Compose

### Run with Docker

```bash
docker compose up -d --build
```

The API will be available at:

```text
http://localhost:8080
```

---

## 🔑 Environment Variables

Create a `.env` file in the project root.

```env
SPRING_PROFILES_ACTIVE=prod

DB_URL=jdbc:postgresql://db:5432/authdb
DB_USER=auth
DB_PASSWORD=auth

REDIS_HOST=redis
REDIS_PORT=6379

JWT_SECRET=your_secret_key_here
JWT_EXPIRATION=900000
```

**Important:** Replace the example JWT secret with a strong, securely generated secret before deploying the application.

---

## 🧩 Application Profiles

The application supports multiple profiles:

- `dev` → local development
- `prod` → production environment

Set the active profile using:

```env
SPRING_PROFILES_ACTIVE=prod
```

---

## 📡 API Endpoints

### 🔐 Authentication

#### Register

```http
POST /auth/register
```

Creates a new user. If the tenant does not exist, it is created automatically.

Example:

```json
{
  "email": "admin@empresa.com",
  "password": "Password123",
  "tenantName": "Empresa A"
}
```

#### Login

```http
POST /auth/login
```

Authentication requires the tenant slug, email, and password.

Example:

```json
{
  "tenantSlug": "empresa-a",
  "email": "admin@empresa.com",
  "password": "Password123"
}
```

#### Refresh Token

```http
POST /auth/refresh
```

Example:

```json
{
  "refreshToken": "<refresh_token>"
}
```

#### Logout

```http
POST /auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json
```

Example:

```json
{
  "refreshToken": "<refresh_token>"
}
```

Returns `204 No Content` when logout succeeds.

---

## 🔒 Protected Routes

Example:

```http
GET /api/admin
Authorization: Bearer <access_token>
```

The service also provides role-protected routes, such as `/api/user`.

---

## 🗄️ Database

Database schema and versioning are managed using Flyway migrations.

Current migrations:

- `V1__init_schema.sql`
- `V2__seed_roles_permissions.sql`
- `V3__add_multi_tenant.sql`
- `V4__redesign_multi_tenant_architecture.sql`
- `V5__hash_refresh_tokens.sql`
- `V6__tenant_scoped_email_uniqueness.sql`

---

## 🧪 Testing

The project includes automated unit and integration tests.

**Testing stack:**

- JUnit 5
- Spring Boot Test
- MockMvc
- Testcontainers
- PostgreSQL
- Redis

Integration tests validate:

- Authentication and authorization.
- Role-based access control.
- Refresh token rotation and reuse detection.
- Logout and token invalidation.
- Tenant isolation.
- Same email address across different tenants.
- Different email domains within the same tenant.
- Stateless HTTP session behavior.

Latest verification:

```text
Tests run: 23
Failures: 0
Errors: 0
Skipped: 0

BUILD SUCCESS
```

Run the test suite using:

```bash
./mvnw clean verify
```

---

## 📁 Project Structure

```text
src/main/java/com/auth/authservice
├── config
├── controller
├── service
├── repository
├── entity
├── security
├── dto
└── exception
```

---

## 📦 Future Improvements

- OAuth2 / OpenID Connect
- API Gateway integration
- Rate limiting
- Audit logs
- Distributed tracing
- Custom tenant domains
- Tenant invitation and membership management

---

## 💡 Notes

This project was designed to simulate a real-world authentication and authorization service, focusing on:

- Security best practices
- Scalable architecture
- Reusable authentication infrastructure
- SaaS multi-tenant design
- Separation of authentication and business services

---

## 👨‍💻 Author

Developed by **Arlindo Fernandes**