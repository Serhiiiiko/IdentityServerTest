using Duende.IdentityServer;
using Duende.IdentityServer.Models;

namespace IdentityServerTest;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResource
            {
                Name = "roles",
                DisplayName = "User roles",
                UserClaims = { "role" }
            }
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
        {
            // E-shop service-specific scopes
            new ApiScope("catalog.read", "Read access to catalog API"),
            new ApiScope("catalog.write", "Write access to catalog API"),
            new ApiScope("basket.read", "Read access to basket API"),
            new ApiScope("basket.write", "Write access to basket API"),
            new ApiScope("discount.read", "Read access to discount API"),
            new ApiScope("discount.write", "Write access to discount API"),
            new ApiScope("ordering.read", "Read access to ordering API"),
            new ApiScope("ordering.write", "Write access to ordering API"),
            
            // Aggregated scopes for convenience
            new ApiScope("eshop.read", "Read access to all E-Shop APIs"),
            new ApiScope("eshop.write", "Write access to all E-Shop APIs"),
            new ApiScope("eshop.fullaccess", "Full access to all E-Shop APIs")
        };

    public static IEnumerable<ApiResource> ApiResources =>
        new ApiResource[]
        {
            new ApiResource("catalog-api", "Catalog API")
            {
                Scopes = { "catalog.read", "catalog.write", "eshop.read", "eshop.write", "eshop.fullaccess" }
            },
            new ApiResource("basket-api", "Basket API")
            {
                Scopes = { "basket.read", "basket.write", "eshop.read", "eshop.write", "eshop.fullaccess" }
            },
            new ApiResource("discount-api", "Discount API")
            {
                Scopes = { "discount.read", "discount.write", "eshop.read", "eshop.write", "eshop.fullaccess" }
            },
            new ApiResource("ordering-api", "Ordering API")
            {
                Scopes = { "ordering.read", "ordering.write", "eshop.read", "eshop.write", "eshop.fullaccess" }
            }
        };

    public static IEnumerable<Client> Clients =>
        new Client[]
        {
            // Machine-to-machine communication between services
            new Client
            {
                ClientId = "eshop.service.client",
                ClientName = "E-Shop Service Client",
                ClientSecrets = { new Secret("service_client_secret".Sha256()) },
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                AllowedScopes = {
                    "catalog.read", "catalog.write",
                    "basket.read", "basket.write",
                    "discount.read", "discount.write",
                    "ordering.read", "ordering.write",
                    "eshop.fullaccess"
                }
            },
            
            // Web application
            new Client
            {
                ClientId = "eshop.web",
                ClientName = "E-Shop Web Application",
                ClientSecrets = { new Secret("web_client_secret".Sha256()) },
                AllowedGrantTypes = GrantTypes.Code,
                RequirePkce = true,

                RedirectUris = { "https://localhost:6065/signin-oidc" },
                PostLogoutRedirectUris = { "https://localhost:6065/signout-callback-oidc" },
                FrontChannelLogoutUri = "https://localhost:6065/signout-oidc",

                AllowOfflineAccess = true,
                AccessTokenLifetime = 3600, // 1 hour
                IdentityTokenLifetime = 300, // 5 minutes
                
                AllowedScopes = {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "roles",
                    "catalog.read",
                    "basket.read", "basket.write",
                    "ordering.read", "ordering.write",
                    "discount.read"
                },
                RequireConsent = false
            },
            
            // Single Page Application
            new Client
            {
                ClientId = "eshop.spa",
                ClientName = "E-Shop SPA",
                ClientUri = "https://localhost:6065",

                AllowedGrantTypes = GrantTypes.Code,
                RequirePkce = true,
                RequireClientSecret = false, // SPA can't keep secrets
                
                RedirectUris = {
                    "https://localhost:6065/authentication/login-callback",
                    "https://localhost:6065/silent-refresh.html"
                },
                PostLogoutRedirectUris = { "https://localhost:6065/authentication/logout-callback" },
                AllowedCorsOrigins = { "https://localhost:6065" },

                AllowOfflineAccess = true,
                AccessTokenLifetime = 3600, // 1 hour
                
                AllowedScopes = {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "roles",
                    "catalog.read",
                    "basket.read", "basket.write",
                    "ordering.read", "ordering.write",
                    "discount.read"
                }
            },
            
            // Mobile application
            new Client
            {
                ClientId = "eshop.mobile",
                ClientName = "E-Shop Mobile App",

                AllowedGrantTypes = GrantTypes.Code,
                RequirePkce = true,
                RequireClientSecret = false,

                RedirectUris = { "com.eshop.mobile:/oauth2redirect" },
                PostLogoutRedirectUris = { "com.eshop.mobile:/signout-callback" },

                AllowOfflineAccess = true, // Enable refresh tokens
                AccessTokenLifetime = 86400, // 24 hours
                RefreshTokenUsage = TokenUsage.OneTimeOnly,
                RefreshTokenExpiration = TokenExpiration.Absolute,
                AbsoluteRefreshTokenLifetime = 2592000, // 30 days
                
                AllowedScopes = {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "roles",
                    "catalog.read",
                    "basket.read", "basket.write",
                    "ordering.read", "ordering.write",
                    "discount.read"
                }
            }
        };
}