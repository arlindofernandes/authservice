# ---------- BUILD STAGE ----------
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src

RUN mvn clean package -DskipTests

# ---------- RUNTIME STAGE ----------
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

RUN groupadd --system authservice \
    && useradd --system --gid authservice --home-dir /app --shell /usr/sbin/nologin authservice

COPY --chown=authservice:authservice --from=builder /app/target/*.jar app.jar

EXPOSE 8080

USER authservice:authservice

ENTRYPOINT ["java", "-jar", "app.jar"]
