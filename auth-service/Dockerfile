# Stage 1: Build with Maven
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Run with Java
FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY --from=build /app/target/auth-service-0.0.1-SNAPSHOT.jar /app/auth-service-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java", "-jar", "/app/auth-service-0.0.1-SNAPSHOT.jar"]
EXPOSE 8082