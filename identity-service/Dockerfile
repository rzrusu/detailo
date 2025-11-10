# --- Stage 1: Build the Application ---
# Use an official Maven image that includes Java 17
FROM maven:3.9-eclipse-temurin-17 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the service's pom.xml
COPY pom.xml .

# Copy the rest of *this service's* source code
COPY src ./src

# Run the Maven build to create the .jar file
# -DskipTests is good practice for container builds
RUN mvn clean install -DskipTests

# --- Stage 2: Create the Final, Lightweight Image ---
# Use a minimal Java 17 JRE image
FROM eclipse-temurin:17-jre-jammy

# Set the working directory
WORKDIR /app

# Copy ONLY the built .jar file from the 'build' stage
# The path is target/<artifactId>-<version>.jar
# We use a wildcard to avoid hard-coding the version
COPY --from=build /app/target/*.jar app.jar

# Expose the port that the application will run on
EXPOSE 8081

# The command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]