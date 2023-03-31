FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["TokenRevocation/TokenRevocation.csproj", "TokenRevocation/"]
RUN dotnet restore "TokenRevocation/TokenRevocation.csproj"
COPY . .
WORKDIR "/src/TokenRevocation"
RUN dotnet build "TokenRevocation.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "TokenRevocation.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "TokenRevocation.dll"]
