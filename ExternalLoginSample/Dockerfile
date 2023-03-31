FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["RefrechToken/RefrechToken.csproj", "RefrechToken/"]
RUN dotnet restore "RefrechToken/RefrechToken.csproj"
COPY . .
WORKDIR "/src/RefrechToken"
RUN dotnet build "RefrechToken.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "RefrechToken.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "RefrechToken.dll"]
