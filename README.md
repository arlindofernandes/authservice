# 🔐 Auth Service

Authentication and Authorization Service built with **Spring Boot**, designed for secure and scalable SaaS applications.

Implements JWT authentication, RBAC, refresh token rotation, and multi-tenant architecture.

---

## ⭐ Highlights

- Multi-tenant architecture (SaaS-ready)
- Domain-based authentication (no tenant input)
- Refresh token rotation with reuse detection
- Redis-based token blacklist

---

## 🚀 Tech Stack

* Java 21
* Spring Boot
* Spring Security
* JWT (jjwt)
* PostgreSQL
* Redis
* Flyway (database migrations)
* Docker

---

## 📌 Features

* ✅ User registration
* ✅ Authentication (JWT)
* ✅ Refresh token with rotation & reuse detection
* ✅ Role-based access control (RBAC)
* ✅ Permissions system
* ✅ Logout with token blacklist (Redis)
* ✅ Protected endpoints
* ✅ Database versioning with Flyway
* ✅ Multi-tenant architecture (SaaS-ready)
* ✅ Domain-based login (no tenant input required)
---

## 🏗️ Architecture

The project follows a layered architecture:

* **Controller** → handles HTTP requests
* **Service** → business logic
* **Repository** → data access
* **Security** → JWT + filters + auth logic
* **DTO** → request/response models
* **Config** → application configuration

---


## 🧩 Multi-Tenant Design

This project implements:

```text
Shared Database + Shared Schema + tenant_id
```

### Key Concepts:

* Each user belongs to a **tenant**
* Tenant is identified by **email domain**
* `tenant_id` is embedded in JWT
* Isolation is enforced using **TenantContext (ThreadLocal)**

### Example:

```text
admin@empresa.com → Tenant: empresa.com
user@empresa.com  → Same tenant
hacker@gmail.com  → Access denied
```

---

## 🔐 Authentication Flow

1. User registers (creates tenant automatically)
2. First user becomes **ADMIN**
3. Other users (same domain) become **USER**
4. Login detects tenant from email domain
5. JWT includes `tenantId`
6. Requests are validated and isolated per tenant

---

## 🔄 Token Flow

```text
Login → Access Token + Refresh Token
↓
Access Token → used in requests
↓
Refresh Token → generates new tokens
↓
Old refresh tokens are invalidated (rotation)
```

---

## 🔒 Security

* Passwords hashed with BCrypt
* JWT signed with secret key
* Token expiration enforced
* Refresh token rotation (prevents replay attacks)
* Role & permission-based authorization
* Token blacklist using Redis
* Multi-tenant isolation (no cross-tenant access)

---

## ⚙️ Running the Project

### 🔧 Requirements

* Docker
* Docker Compose

---

### ▶️ Run with Docker

```bash
docker compose up --build
```

The application will be available at:

```
http://localhost:${SERVER_PORT:8080}
```

---

## 🔑 Environment Variables

Create a `.env` file:

```env
SPRING_PROFILES_ACTIVE=prod

DB_URL=jdbc:postgresql://db:5432/authdb
DB_USERNAME=auth
DB_PASSWORD=auth

REDIS_HOST=redis
REDIS_PORT=6379

JWT_SECRET=your_secret_key_here
JWT_EXPIRATION=900000
```
---

## 🧩 Application Profiles

The application supports multiple profiles:

- `dev` → local development
- `prod` → production environment

Set using:

```env
SPRING_PROFILES_ACTIVE=prod
```

---

## 📡 API Endpoints

### 🔐 Authentication

#### Register

```
POST /auth/register
```

Example:

```json
{
  "email": "admin@empresa.com",
  "password": "123456",
  "tenantName": "Empresa A"
}
```

---

#### Login

```
POST /auth/login
```

```json
{
  "email": "admin@empresa.com",
  "password": "123456"
}
```

---

#### Refresh Token

```
POST /auth/refresh
```

---

#### Logout

```
POST /auth/logout
```

---

## 🔒 Protected Routes

Example:

```
GET /api/test
Authorization: Bearer <access_token>
```

---

## 🗄️ Database

Managed with **Flyway migrations**:

* `V1__init_schema.sql`
* `V2__seed_roles_permissions.sql`
* `V3__multi_tenant.sql`

---

## 📁 Project Structure

```
src/main/java/com/auth/authservice
 ├── config
 ├── controller
 ├── service
 ├── repository
 ├── entity
 ├── security
 ├── dto
 ├── exception
```

---

## 🧪 Testing

Manual testing:

* Insomnia
* Postman

Planned:
- JUnit (unit tests)
- Integration tests
- Testcontainers (database testing)

---

## 📦 Future Improvements

* OAuth2 / OpenID Connect
* API Gateway integration
* Rate limiting
* Audit logs
* Distributed tracing

---

## 💡 Notes

This project was designed to simulate a **real-world authentication service**, focusing on:

- Security best practices
- Scalable architecture
- SaaS multi-tenant design

---

## 👨‍💻 Author

Developed by **Arlindo Fernandes**