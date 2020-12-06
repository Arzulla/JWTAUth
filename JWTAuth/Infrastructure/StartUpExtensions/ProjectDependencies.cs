using JWTAuth.Repository;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JWTAuth.Infrastructure.StartUpExtensions
{
    public static class ProjectDependencies
    {
        public static IServiceCollection AddProjectDependencies(this IServiceCollection services,
         IConfiguration configuration)
        {
            services.AddScoped<ITokenRepository, TokenRepository>();

            return services;
        }
    }
}
