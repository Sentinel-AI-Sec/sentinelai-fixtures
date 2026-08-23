# The code->infra join for fixture 05.
#
# LABEL org.sentinelai.image must normalize to the same coordinate as the container image field
# in infra/main.tf ("registry.hub.docker.com/iot/device-gateway:4.1.2"). Both reduce to
# "iot/device-gateway" once the registry prefix and tag are stripped.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
LABEL org.sentinelai.image="iot/device-gateway"
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/DeviceGateway/DeviceGateway.csproj ./
RUN dotnet restore
COPY src/DeviceGateway/. .
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# INFRA-12 (CWE-798): the firmware signing key baked into the image.
#
# The one credential that could have made CODE-05's signature check meaningful, shipped to
# anyone who can pull the image. Even if somebody fixed CODE-05 tomorrow and started verifying
# signatures, this would mean an attacker can produce valid ones. Dummy fixture value.
ENV FIRMWARE_SIGNING_KEY="fixture-dummy-signing-key-000111"

# INFRA-13 (CWE-250): no USER directive - runs as root. Checkov CKV_DOCKER_3.
ENTRYPOINT ["dotnet", "DeviceGateway.dll"]
