using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

List<string> blackLists = new();

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie", opt =>
    {
        opt.Events.OnValidatePrincipal = ctx =>
        {
            // this is how you would reach to an IoC ISP Service.
            // ctx.HttpContext.RequestServices.GetRequiredService<>();

            var result = blackLists.Contains(ctx.Principal?.FindFirstValue("session"));

            if (result)
            {
                ctx.RejectPrincipal();
                ctx.HttpContext.Response.Redirect("/login");
            }
            
            
            
            return Task.CompletedTask;
        };
    });

var app = builder.Build();

app.MapGet("/login", async () =>
    Results.SignIn(
        new ClaimsPrincipal(
            new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()), 
                new Claim("session", Guid.NewGuid().ToString())
            },
            "cookie")),
        new AuthenticationProperties(),
        "cookie"
    ));


app.MapGet("/user", (ClaimsPrincipal user)
    => user.Claims.Select(x => new { x.Type, x.Value }).ToList());

app.MapGet("/black-list", (string userSession)
    => blackLists.Add(userSession));

app.Run();