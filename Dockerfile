# Image name normalizes to "tinyapp/order" after stripping the registry
# prefix + tag - this MUST match main.tf's flagship ECS task image field
# ("registry.hub.docker.com/tinyapp/order:1.4.2") for the code->infra
# join to resolve as "inferred" confidence (SEC-19).
#
# A Dockerfile has no field naming the image it builds - that name comes from
# whatever `docker build -t <name>` invocation builds it, and this fixture has
# no CI script to read it from. SEC-19's DockerfileImageNameExtractor therefore
# reads one explicit, self-declared signal, the LABEL below. Without it the
# code->infra seam has nothing to compare and the golden chain above is not
# reconstructible, so the label is load-bearing fixture data, not decoration.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
LABEL org.sentinelai.image="tinyapp/order"
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
