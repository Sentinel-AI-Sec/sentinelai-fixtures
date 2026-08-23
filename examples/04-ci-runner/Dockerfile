# The code->infra join for fixture 04.
#
# LABEL org.sentinelai.image must normalize to the same coordinate as the container image in
# k8s/runner-deployment.yaml ("registry.hub.docker.com/ci/build-runner:4.2.0"). Both reduce to
# "ci/build-runner".

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
LABEL org.sentinelai.image="ci/build-runner"
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/BuildRunner/BuildRunner.csproj ./
RUN dotnet restore
COPY src/BuildRunner/. .
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# INFRA-17 (CWE-250): no USER directive. Redundant here, since the pod spec sets runAsUser: 0
# and privileged: true anyway - but worth having as its own finding, because a hardened pod spec
# would still be undone by an image that insists on root.
#
# INFRA-18 (CWE-829): docker CLI installed into the runtime image so builds can talk to the
# mounted socket. It is the tooling that makes INFRA-11 usable.
RUN apt-get update && apt-get install -y --no-install-recommends docker.io && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["dotnet", "BuildRunner.dll"]
