using JWTAuth.Models.Identity;
using JWTAuth.Repository;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

namespace JWTAuth.Infrastructure.StartUpExtensions
{
    public static class AspNetIdentityDependencies
    {
        public static IServiceCollection AddAspNetIdentityDependencies(this IServiceCollection services,
        IConfiguration Configuration)
        {

            //For Identity
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 7;
                options.User.RequireUniqueEmail = false;
            }).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

            //Adding Authentication
            services.AddAuthentication(option =>
            {
                option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })

            //Adding JWT Bearer
          .AddJwtBearer(options =>
          {
              options.SaveToken = true;
              options.RequireHttpsMetadata = false;
              options.TokenValidationParameters = new TokenValidationParameters()
              {

                  IssuerSigningKey = new SymmetricSecurityKey(
                           Encoding.UTF8.GetBytes(Configuration["Auth:Jwt:Key"])),
                  ValidAudience = Configuration["Auth:Jwt:Audience"],
                  ClockSkew = TimeSpan.Zero,
                  // security switches
                  RequireExpirationTime = true,
                  ValidateIssuer = true,
                  ValidateIssuerSigningKey = true,
                  ValidateAudience = true,
                  ValidIssuer = Configuration["Auth:Jwt:Issuer"],
              };
          });

            return services;
        }
    }
}
