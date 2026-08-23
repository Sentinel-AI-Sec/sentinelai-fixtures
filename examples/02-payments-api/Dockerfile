# The code->infra join for this fixture.
#
# LABEL org.sentinelai.image must normalize to the same coordinate as main.tf's container image
# field ("registry.hub.docker.com/fintech/payments:2.1.0"). Strip the registry prefix and the
# tag and both sides read "fintech/payments". Without the label there is nothing to compare and
# the chain from CODE-01 to INFRA-01 cannot be reconstructed.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
LABEL org.sentinelai.image="fintech/payments"
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/PaymentsApi/PaymentsApi.csproj ./
RUN dotnet restore
COPY src/PaymentsApi/. .
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# INFRA-17 (CWE-798): the PSP key is baked into the image as an environment variable, so it is
# readable by anyone who can pull the image - which defeats the point of the secret store the
# flagship chain works so hard to reach. Dummy fixture value.
ENV PSP_FALLBACK_KEY="psp_live_fixture_dummy_key_000111"

# INFRA-18 (CWE-250): no USER directive, so the container runs as root. Checkov CKV_DOCKER_3.
ENTRYPOINT ["dotnet", "PaymentsApi.dll"]
