using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<Time>();

builder.Services.AddAuthentication("cookie")
    // The AddCookie is necessary for the AddOAuth() to work,
    // otherwise enter an endless loop and throws exception 
    .AddCookie("cookie")
    .AddOAuth("github", o =>
    {
        o.SignInScheme = "cookie";
        o.ClientId = "58ef6d8ebb2c2df7dade" ;
        o.ClientSecret = "b894aa13a3f29e4525ac880f2252fbdf9ba9e6c3";

        o.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        o.TokenEndpoint = "https://github.com/login/oauth/access_token";
        o.CallbackPath = "/oauth/github-cb";

        o.UserInformationEndpoint = "https://api.github.com/user";
        o.SaveTokens = true;

        o.ClaimActions.MapJsonKey("sub","id");
        o.ClaimActions.MapJsonKey(claimType: ClaimTypes.Name,"login");

        o.Events.OnCreatingTicket = async (ctx) =>
        {
            // Request services from IoC, can be used to persist data to a Db.
            // ctx.HttpContext.RequestServices.GetRequiredService<>();
            
            using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer",ctx.AccessToken);
            var result = await ctx.Backchannel.SendAsync(request);
            var user = await result.Content.ReadFromJsonAsync<JsonElement>();
            ctx.RunClaimActions(user);
        };
    });

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/", (HttpContext httpContext) => 
    httpContext.User.Claims.Select(x => new {x.Type, x.Value}).ToList());

app.MapGet("/login", () => 
    Results.Challenge(
        new AuthenticationProperties()
        {
            // Redirect back to '/' after a successful auth. 
            RedirectUri = "https://localhost:5000/"
        },
        authenticationSchemes:new List<string>(){"github"}));


app.Run();

public class Time
{
    public DateTimeOffset CurrentTimeUtc => DateTimeOffset.UtcNow.DateTime;
}