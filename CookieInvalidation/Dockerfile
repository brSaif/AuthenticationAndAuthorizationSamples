FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["CookieInvalidationTokenRevocation/CookieInvalidationTokenRevocation.csproj", "CookieInvalidationTokenRevocation/"]
RUN dotnet restore "CookieInvalidationTokenRevocation/CookieInvalidationTokenRevocation.csproj"
COPY . .
WORKDIR "/src/CookieInvalidationTokenRevocation"
RUN dotnet build "CookieInvalidationTokenRevocation.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "CookieInvalidationTokenRevocation.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "CookieInvalidationTokenRevocation.dll"]
