using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace CPChem.Security.JwtValidation
{
    public sealed class JwtOptions
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string TenantId { get; set; }
    }

    public static class JwtAuthExtensions
    {
        public static IServiceCollection AddAuthentication(
            this IServiceCollection services,
            JwtOptions jwtOptions)
        {
            _ = services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Audience = jwtOptions.Audience;
                    options.Authority = jwtOptions.Issuer;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidIssuer = jwtOptions.Issuer,
                        ValidAudience = jwtOptions.Audience,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = false,
                    };

                    options.Events ??= new JwtBearerEvents();

                    options.Events.OnTokenValidated = context =>
                    {
                        var token = (JwtSecurityToken)context.SecurityToken;
                        var tid = token.Claims.FirstOrDefault(c => c.Type == "tid");
                        if (tid == null ||
                            string.IsNullOrEmpty(tid.Value) ||
                            tid.Value != jwtOptions.TenantId)
                        {
                            context.Fail("Invalid Tenant ID ('tid') in token.");
                        }

                        return Task.CompletedTask;
                    };
                });

            return services;
        }
    }
}
