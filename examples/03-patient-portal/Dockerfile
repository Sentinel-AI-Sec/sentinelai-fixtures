# The code->infra join for fixture 03.
#
# LABEL org.sentinelai.image must normalize to the same coordinate as the container image field
# in infra/main.tf ("registry.hub.docker.com/health/patient-portal:1.9.0"). Both reduce to
# "health/patient-portal" once the registry prefix and tag are stripped.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
LABEL org.sentinelai.image="health/patient-portal"
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/PatientPortal/PatientPortal.csproj ./
RUN dotnet restore
COPY src/PatientPortal/. .
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# INFRA-14 (CWE-250): no USER directive - runs as root. Checkov CKV_DOCKER_3.
#
# INFRA-15 (CWE-1104): the base image is pinned only to a major tag, so what actually ships
# changes without any change to this file or the lock file.
ENTRYPOINT ["dotnet", "PatientPortal.dll"]
