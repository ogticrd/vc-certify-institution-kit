# Multi-stage build: Maven compile inside Docker (no JDK on host).
# Build context: inji-rd-certify repo root (parent of institution-kit).

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

COPY pom.xml .
COPY certify-core/pom.xml certify-core/
COPY certify-integration-api/pom.xml certify-integration-api/
COPY certify-service/pom.xml certify-service/

RUN mvn -pl certify-service -am dependency:go-offline -DskipTests -Dmaven.gitcommitid.skip=true -q || true

COPY certify-core certify-core
COPY certify-integration-api certify-integration-api
COPY certify-service certify-service

COPY certify-service/loader_path/certify/ /plugin-src/
RUN mkdir -p /plugin && set -e; \
    jar="$(ls /plugin-src/restapi-dataprovider-plugin*.jar 2>/dev/null | head -1)"; \
    if [ -z "${jar}" ] && [ -f /plugin-src/restapi-dataprovider-plugin.jar ]; then \
      jar="/plugin-src/restapi-dataprovider-plugin.jar"; \
    fi; \
    if [ -z "${jar}" ]; then \
      echo "ERROR: restapi-dataprovider-plugin*.jar not found in certify-service/loader_path/certify/" >&2; \
      exit 1; \
    fi; \
    cp "${jar}" /plugin/restapi-dataprovider-plugin.jar

# git-commit-id-plugin needs .git (not copied into the image); skip it for Docker builds
RUN mvn -pl certify-service -am package -DskipTests -Dmaven.gitcommitid.skip=true -q

FROM eclipse-temurin:21-jre

ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001
ARG loader_path=/home/${container_user}/additional_jars/

RUN apt-get -y update \
  && apt-get install -y --no-install-recommends unzip wget \
  && groupadd -g ${container_user_gid} ${container_user_group} \
  && useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/sh -m ${container_user} \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /home/${container_user}
ENV work_dir=/home/${container_user}
ENV loader_path_env=${loader_path}
ENV active_profile_env=default,institution
ENV spring_config_label_env=master
ENV spring_config_url_env=
ENV install_hsm_client=false
ENV download_hsm_client=false

RUN mkdir -p ${loader_path} /home/${container_user}/CERTIFY_PKCS12 /home/${container_user}/config

COPY --from=build /build/certify-service/target/certify-service-*.jar /home/${container_user}/certify-service.jar
COPY --from=build /plugin/restapi-dataprovider-plugin.jar ${loader_path}
COPY certify-service/configure_start.sh /home/${container_user}/configure_start.sh

RUN chmod +x /home/${container_user}/configure_start.sh \
  && chown -R ${container_user}:${container_user} /home/${container_user}

USER ${container_user_uid}:${container_user_gid}

EXPOSE 8090

ENTRYPOINT ["./configure_start.sh"]
CMD ["java", "-jar", "-Dloader.path=${loader_path_env}", "-Dspring.cloud.config.enabled=false", "-Dspring.profiles.active=${active_profile_env}", "-Dspring.config.name=certify", "-Dspring.config.location=file:/home/mosip/config/", "certify-service.jar"]
