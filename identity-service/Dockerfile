# --- Stage 1: Build the Application ---
# Use an official Maven image that includes Java 17
FROM maven:3.9-eclipse-temurin-17 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the parent POM first (needed for multi-module builds)
COPY pom.xml ./pom.xml

# Copy the service's pom.xml
COPY identity-service/pom.xml ./identity-service/pom.xml

# Copy the rest of *this service's* source code
COPY identity-service/src ./identity-service/src

# Change to the service directory and run the Maven build
WORKDIR /app/identity-service
RUN mvn clean install -DskipTests

# --- Stage 2: Create the Final, Lightweight Image ---
# Use a minimal Java 17 JRE image
FROM eclipse-temurin:17-jre-jammy

# Set the working directory
WORKDIR /app

# Copy ONLY the built .jar file from the 'build' stage
# The path is target/<artifactId>-<version>.jar
# We use a wildcard to avoid hard-coding the version
COPY --from=build /app/identity-service/target/*.jar app.jar

# Create a non-root user and group
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /home/appuser -m -s /bin/bash appuser && \
    chown -R appuser:appuser /app

# Expose the port that the application will run on
EXPOSE 8081

# Switch to non-root user
USER appuser

# The command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]