using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var rsaKey = RSA.Create();
List<string> blackLists = new();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddJwtBearer("jwt", opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false
        };

        opt.Events = new JwtBearerEvents()
        {
            OnMessageReceived = (ctx) =>
            {
                if (ctx.Request.Query.ContainsKey("t"))
                {
                    ctx.Token = ctx.Request.Query["t"];

                    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(ctx.Token));
                    var hashString = Convert.ToBase64String(hash);
                    if (blackLists.Contains(hashString))
                    {
                        ctx.Fail("Invalid token");
                    }
                }
                
                
                
                return  Task.CompletedTask;
            }
        };

        opt.Configuration = new OpenIdConnectConfiguration { SigningKeys = { new RsaSecurityKey(rsaKey) } };

        opt.MapInboundClaims = false;
    });

var app = builder.Build();

app.MapGet("login", () =>
{
    var handler = new JsonWebTokenHandler();
    var key = new RsaSecurityKey(rsaKey);
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "http//localhost:5000",
        Subject = new ClaimsIdentity(new Claim[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new ("session", Guid.NewGuid().ToString())
        }),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
    });

    return token;
});

app.MapGet("user", 
    (ClaimsPrincipal principal) => principal
            .Claims
            .Select(x => new { x.Type, x.Value })
            .ToList());

app.MapGet("/black-list", (string token)
    =>
{
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
    var hashString = Convert.ToBase64String(hash);
    blackLists.Add(hashString);
});

app.Run();