# 🔐 Auth Service

Authentication and Authorization Service built with **Spring Boot**, implementing secure user management with **JWT**, **roles**, and **permissions**.

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
* ✅ Refresh token
* ✅ Role-based access control (RBAC)
* ✅ Permissions system
* ✅ Logout with token blacklist (Redis)
* ✅ Protected endpoints
* ✅ Database versioning with Flyway

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
http://localhost:8080
```

---

## 🔑 Environment Variables

Create a `.env` file:

```env
DB_URL=jdbc:postgresql://db:5432/authdb
DB_USERNAME=auth
DB_PASSWORD=auth

REDIS_HOST=redis
REDIS_PORT=6379

JWT_SECRET=your_secret_key_here
JWT_EXPIRATION=900000
```

---

## 📡 API Endpoints

### 🔐 Authentication

#### Register

```
POST /auth/register
```

#### Login

```
POST /auth/login
```

#### Refresh Token

```
POST /auth/refresh
```

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

## 🧠 Authentication Flow

1. User registers
2. User logs in → receives access + refresh token
3. Access token is used for requests
4. Refresh token generates new access token
5. Logout invalidates token via Redis blacklist

---

## 🛡️ Security

* Passwords hashed with BCrypt
* JWT signed with secret key
* Token expiration enforced
* Refresh token mechanism
* Role & permission-based authorization
* Token blacklist with Redis

---

## 🗄️ Database

Managed with **Flyway migrations**:

* `V1__init_schema.sql`
* `V2__seed_roles_permissions.sql`

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

You can test using:

* Insomnia
* Postman

---

## 📦 Future Improvements

* OAuth2 / OpenID Connect
* API Gateway integration
* Rate limiting
* Audit logs
* Multi-tenancy support

---

## 👨‍💻 Author

Developed by Arlindo Fernandes
