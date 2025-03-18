using Duende.IdentityServer;
using IdentityServerTest.Data;
using IdentityServerTest.Models;
using IdentityServerTest.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IdentityServerTest;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        var assemblyName = typeof(HostingExtensions).GetTypeInfo().Assembly.GetName().Name;
        var connectionString = builder.Configuration.GetConnectionString("IdentityConnection");

        builder.Services.AddControllersWithViews();
        builder.Services.AddRazorPages();

        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                // Read allowed origins from configuration
                var allowedOrigins = builder.Configuration
                    .GetSection("Cors:AllowedOrigins")
                    .Get<string[]>() ?? Array.Empty<string>();

                policy.WithOrigins(allowedOrigins)
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
        });

        // Configure database context
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
        {
            if (builder.Environment.IsDevelopment())
            {
                options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
            }
            else
            {
                options.UseSqlServer(connectionString, sqlOptions =>
                {
                    sqlOptions.MigrationsAssembly(assemblyName);
                    sqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null
                    );
                });
            }
        });

        // Configure identity
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            // Password settings
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireLowercase = true;

            // Lockout settings
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;

            // User settings
            options.User.RequireUniqueEmail = true;
            options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

            options.SignIn.RequireConfirmedAccount = false;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

        var identityServerBuilder = builder.Services
            .AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
                options.EmitStaticAudienceClaim = true;

                // Prevent CSRF attacks
                options.Authentication.CookieSameSiteMode = Microsoft.AspNetCore.Http.SameSiteMode.Lax;

                // Cookie configuration
                options.Authentication.CookieLifetime = TimeSpan.FromHours(10);
                options.Authentication.CookieSlidingExpiration = true;
            })
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryApiResources(Config.ApiResources)
            .AddInMemoryClients(Config.Clients)
            .AddAspNetIdentity<ApplicationUser>();

        // Configure signing credentials based on environment
        if (builder.Environment.IsDevelopment())
        {
            // For development, use developer signing credential
            identityServerBuilder.AddDeveloperSigningCredential();
        }
        else
        {
            // For production, use proper certificate
            var certificatePath = builder.Configuration["IdentityServer:Certificate:Path"];
            var certificatePassword = builder.Configuration["IdentityServer:Certificate:Password"];

            if (!string.IsNullOrEmpty(certificatePath) && File.Exists(certificatePath))
            {
                var certificate = new X509Certificate2(certificatePath, certificatePassword);
                identityServerBuilder.AddSigningCredential(certificate);
            }
            else
            {
                // Fallback to using a key from configuration if certificate is not available
                var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration["IdentityServer:Key"]));
                identityServerBuilder.AddSigningCredential(key, SecurityAlgorithms.HmacSha256);

                Log.Warning("Using symmetric key for signing credentials. This is not recommended for production.");
            }
        }

        // Configure authentication for API endpoints
        builder.Services.AddAuthentication()
             .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
             {
                 options.Authority = builder.Configuration["IdentityServer:Authority"];
                 options.TokenValidationParameters = new TokenValidationParameters
                 {
                     ValidateAudience = false,
                     ValidateIssuer = true,
                     ValidateLifetime = true,
                     ClockSkew = TimeSpan.FromMinutes(5)
                 };
             });

        // Configure authorization policies
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("RequireAdminRole", policy =>
                policy.RequireRole("Admin"));

            options.AddPolicy("RequireSupportRole", policy =>
                policy.RequireRole("Admin", "Support"));

            options.AddPolicy("RequireRegisteredUser", policy =>
                policy.RequireRole("Admin", "Support", "Registered"));

            options.AddPolicy("CatalogFullAccess", policy =>
                policy.RequireAssertion(context =>
                    context.User.IsInRole("Admin") ||
                    context.User.HasClaim(c => c.Type == "scope" && c.Value == "catalog.write")));

            options.AddPolicy("CatalogReadAccess", policy =>
                policy.RequireAssertion(context =>
                    context.User.IsInRole("Admin") ||
                    context.User.IsInRole("Support") ||
                    context.User.HasClaim(c => c.Type == "scope" &&
                        (c.Value == "catalog.read" || c.Value == "catalog.write" || c.Value == "eshop.read" || c.Value == "eshop.fullaccess"))));
        });

        // Add services for managing users and roles
        builder.Services.AddScoped<IUserService, UserService>();
        builder.Services.AddScoped<IRoleService, RoleService>();

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseCors();

        app.UseRouting();

        app.UseIdentityServer();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapDefaultControllerRoute();
        app.MapRazorPages();

        return app;
    }
}