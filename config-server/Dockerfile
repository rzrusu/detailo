# --- Stage 1: Build the Application ---
# Use an official Maven image that includes Java 25
FROM maven:3.9-eclipse-temurin-25 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the parent pom.xml and the service's pom.xml
# (This helps Docker cache dependencies)
COPY ../pom.xml .
COPY pom.xml .

# Copy the rest of *this service's* source code
COPY src ./src

# Run the Maven build to create the .jar file
# -DskipTests is good practice for container builds
RUN mvn clean install -DskipTests

# --- Stage 2: Create the Final, Lightweight Image ---
# Use a minimal Java 25 JRE image
FROM eclipse-temurin:25-jre-jammy

# Set the working directory
WORKDIR /app

# Copy ONLY the built .jar file from the 'build' stage
# The path is target/<artifactId>-<version>.jar
# We use a wildcard to avoid hard-coding the version
COPY --from=build /app/target/*.jar app.jar

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Expose the port that the application will run on
# (This is just documentation; 8761 is for Eureka, 8888 for Config, etc.)
# The actual port is set in your application.properties
EXPOSE 8888

# The command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]