using System.Security.Claims;
using CookieJwtAuth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var keyManager = new KeyManager();
builder.Services.AddSingleton(keyManager);
builder.Services.AddDbContext<IdentityDbContext>(opt
    => opt.UseInMemoryDatabase("myDB"));


builder.Services.AddIdentity<IdentityUser, IdentityRole>(o
        =>
    {
        o.User.RequireUniqueEmail = false;
        o.Password.RequireDigit = false;
        o.Password.RequiredLength = 4;
        o.Password.RequireLowercase = false;
        o.Password.RequireUppercase = false;
        o.Password.RequireNonAlphanumeric = false;
    })
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddDefaultTokenProviders();


builder.Services.AddAuthentication()
    .AddJwtBearer("jwt", o =>
    {
        o.TokenValidationParameters = new()
        {
            ValidateAudience = false,
            ValidateIssuer = false
        };

        // to consume the jwt token
        o.Events = new JwtBearerEvents()
        {
            // this where to intercept the token
            OnMessageReceived = ctx =>
            {
                if (ctx.Request.Query.TryGetValue("t", out var token))
                {
                    ctx.Token = token;
                }

                return Task.CompletedTask;
            }
        };

        o.Configuration = new OpenIdConnectConfiguration()
        {
            SigningKeys = { new RsaSecurityKey(keyManager.Rsakey) }
        };

        o.MapInboundClaims = false;
    });


builder.Services.AddAuthorization(o =>
{
    o.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, "jwt")
        .Build();
    
    
    o.AddPolicy("the_policy", pb => 
        pb
            .RequireAuthenticatedUser()
            .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, "jwt")
            .RequireClaim("role", "janitor"));
    
    
    o.AddPolicy("cookie_policy", pb => 
        pb
            .RequireAuthenticatedUser()
            .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
            .RequireClaim("role", "janitor"));
    
    o.AddPolicy("token_policy", pb => 
        pb
            .RequireAuthenticatedUser()
            .AddAuthenticationSchemes("jwt")
            .RequireClaim("role", "janitor"));
});

var app = await builder.BuildAndSetup();

app.MapGet("/", (ClaimsPrincipal user) 
    => user.Claims.Select(c => KeyValuePair.Create(c.Type, c.Value)))
    .RequireAuthorization();

app.MapGet("/secret", () => "secret").RequireAuthorization("the_policy");
app.MapGet("/secret-cookie", () => "Cookie secrets")
    .RequireAuthorization("cookie_policy");
app.MapGet("/secret-token", () => "Token secrets")
    .RequireAuthorization("token_policy");

app.MapGet("/cookie/sign-in", async (SignInManager<IdentityUser> signInManager) 
    =>
{
    await signInManager.PasswordSignInAsync("test@test.com", "password", false, false);
});

app.MapGet("/jwt/sign-in", async (KeyManager keyManager, 
    IUserClaimsPrincipalFactory<IdentityUser> claimsPrincipalFactory,
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager
    ) =>
{
    var user = await userManager.FindByEmailAsync("test@test.com");
    var result = await signInManager.CheckPasswordSignInAsync(user, "password", false);
    if (result.Succeeded)
    {
        var claimsPrincipal = await claimsPrincipalFactory.CreateAsync(user);
        var identity = claimsPrincipal.Identities.First();
        
        identity.AddClaim(new Claim("amr", "pwd"));
        identity.AddClaim(new Claim("method", "jwt"));
        
        var handler = new JsonWebTokenHandler();
        var key = new RsaSecurityKey(keyManager.Rsakey);
        var token = handler.CreateToken(new SecurityTokenDescriptor()
        {
            Issuer = "http://localhost:5000",
            Subject = identity,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });

        return token;
    }

    return "FAILED AUTHENTICATION";
});

app.Run();