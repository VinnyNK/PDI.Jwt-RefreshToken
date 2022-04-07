using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace PDI.JwtWithRefreshToken.Configuration;

public static class JwtConfiguration
{
    public static IServiceCollection AddAuthenticationConfig(this IServiceCollection services, IConfiguration configuration)
    {

        var key = Encoding.UTF8.GetBytes(configuration["JWT:Secret"]);
        services.AddAuthentication(x =>
        {
            x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(x =>
        {
            x.RequireHttpsMetadata = false;
            x.SaveToken = true;
            x.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = configuration["JWT:ValidIssuer"],
                ValidateAudience = true,
                ValidAudience = configuration["JWT:ValidAudience"],
                ValidateLifetime = true,
                ValidateActor = true,
                ClockSkew = TimeSpan.Zero
            };
        });

        return services;
    }
}