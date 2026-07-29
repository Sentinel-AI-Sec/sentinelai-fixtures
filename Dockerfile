# Image name normalizes to "tinyapp/order" after stripping the registry
# prefix + tag - this MUST match main.tf's flagship ECS task image field
# ("registry.hub.docker.com/tinyapp/order:1.4.2") for the code->infra
# join to resolve as "inferred" confidence (SEC-19).

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/OrderApp/OrderApp.csproj ./
RUN dotnet restore
COPY src/OrderApp/. .
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# VULN (INFRA-07): secret baked in via ENV (dummy, non-functional value -
# fixture only, never a real credential).
ENV ORDER_SVC_API_KEY="demo-fixture-dummy-key-not-real-000111"

# VULN (INFRA-08): no USER directive - container runs as root.
# Trivy/Checkov: missing non-root user.
ENTRYPOINT ["dotnet", "OrderApp.dll"]
