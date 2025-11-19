using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Ocelot.Cache.CacheManager;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OcelotAPIGateway
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
            builder.Configuration.AddJsonFile("ocelot.json", optional: false, reloadOnChange: true);
            builder.Services
            .AddOcelot()
            .AddCacheManager(x => x.WithDictionaryHandle());
            // Enable debug logging to console
            builder.Logging.ClearProviders();
            builder.Logging.AddConsole();
            builder.Logging.SetMinimumLevel(LogLevel.Debug);
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAngularClient", policy =>
                {
                    policy.WithOrigins("http://localhost:4200")
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials();
                });
            });
            builder.Services.AddAuthorization();

            // Ensure this matches the AuthenticationProviderKey in ocelot.json
            var endPointAuthKey = builder.Configuration["Keys:EndPointAuthKey"] ?? "eShopFlixEndPointKey@12345678";
            // add at startup before token processing (temporary)
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = endPointAuthKey;
                options.DefaultChallengeScheme = endPointAuthKey;
            })
            .AddJwtBearer(endPointAuthKey, options =>
            {
                options.RequireHttpsMetadata = false; // toggle as appropriate
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? string.Empty)),
                    // Adjust RoleClaimType if your token uses a different claim name
                    //RoleClaimType = ClaimTypes.Role // or "role" or "roles" depending on token
                };

                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = ctx =>
                    {
                        var authHeader = ctx.Request.Headers["Authorization"].ToString();
                        Console.WriteLine($"[Jwt] OnMessageReceived path={ctx.Request.Path} AuthorizationHeader='{authHeader}'");
                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = ctx =>
                    {
                        Console.WriteLine($"[Jwt] OnAuthenticationFailed: {ctx.Exception?.GetType().FullName}: {ctx.Exception?.Message}");
                        if (ctx.Exception != null)
                        {
                            Console.WriteLine(ctx.Exception.ToString());
                        }
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = ctx =>
                    {
                        Console.WriteLine($"[Jwt] OnTokenValidated: Subject='{ctx.Principal?.Identity?.Name}' ClaimsCount={ctx.Principal?.Claims?.Count() ?? 0}");
                        foreach (var c in ctx.Principal?.Claims ?? Enumerable.Empty<Claim>())
                        {
                            Console.WriteLine($"  Claim: {c.Type} = {c.Value}");
                        }
                        return Task.CompletedTask;
                    },
                    OnChallenge = ctx =>
                    {
                        Console.WriteLine($"[Jwt] OnChallenge: Error='{ctx.Error}' ErrorDescription='{ctx.ErrorDescription}'");
                        return Task.CompletedTask;
                    },
                    OnForbidden = ctx =>
                    {
                        Console.WriteLine($"[Jwt] OnForbidden: path={ctx.Request.Path}");
                        return Task.CompletedTask;
                    }
                };
            });

            var app = builder.Build();

            app.UseAuthentication();
            app.UseAuthorization();

            app.Map("/", () => "Hello World!");
            app.Use(async (context, next) =>
            {
                var requestId = context.Request.Headers["RequestId"].FirstOrDefault();
                var clientId = context.Request.Headers["ClientId"].FirstOrDefault();

                Console.WriteLine($"[Gateway] RequestId: {requestId}, ClientId: {clientId}");
                Console.WriteLine($"[Middleware] Path: {context.Request.Path}, Method: {context.Request.Method}");
                await next.Invoke();
            });
            app.UseCors("AllowAngularClient");
            // Ocelot must run after auth middleware
            app.UseOcelot().Wait();

            app.Run();
        }
    }
}