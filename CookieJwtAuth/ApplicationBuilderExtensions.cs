using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace CookieJwtAuth;

public static class ApplicationBuilderExtensions
{
    public static async Task<WebApplication> BuildAndSetup(this WebApplicationBuilder builder)
    {
        var app =  builder.Build();
        using var scope = app.Services.CreateScope();
        
        var usrMgr = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = new IdentityUser() { UserName = "test@test.com", Email = "test@test.com" };
        await usrMgr.CreateAsync(user, "password");
        await usrMgr.AddClaimAsync(user, new Claim("role", "janitor"));
        
        return app;
    }
    
}