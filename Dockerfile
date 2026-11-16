# syntax=docker/dockerfile:1.7

# ---- build ------------------------------------------------------------------------------------
FROM eclipse-temurin:24-jdk AS build
WORKDIR /workspace
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN --mount=type=cache,target=/root/.m2 ./mvnw -B -q dependency:go-offline
COPY src/ src/
RUN --mount=type=cache,target=/root/.m2 ./mvnw -B -q package -DskipTests \
    && java -Djarmode=tools -jar target/superduperdrive-*.jar extract --layers --launcher --destination extracted

# ---- run --------------------------------------------------------------------------------------
FROM eclipse-temurin:24-jre
RUN groupadd --system --gid 10001 sdd \
    && useradd --system --uid 10001 --gid sdd --home-dir /app --shell /usr/sbin/nologin sdd \
    && mkdir -p /app/data \
    && chown -R sdd:sdd /app
WORKDIR /app
COPY --from=build --chown=sdd:sdd /workspace/extracted/dependencies/ ./
COPY --from=build --chown=sdd:sdd /workspace/extracted/spring-boot-loader/ ./
COPY --from=build --chown=sdd:sdd /workspace/extracted/snapshot-dependencies/ ./
COPY --from=build --chown=sdd:sdd /workspace/extracted/application/ ./
USER 10001:10001
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
VOLUME ["/app/data"]
EXPOSE 8085
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]
