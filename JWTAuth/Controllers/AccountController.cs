using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AutoMapper;
using JWTAuth.Authentication;
using JWTAuth.Infrastructure.Mappers;
using JWTAuth.Models.Identity;
using JWTAuth.Models.RequestModel;
using JWTAuth.Models.ResponseModel;
using JWTAuth.Repository;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ITokenRepository _tokenRepository;
        private readonly IMapper _mapper;

        public AccountController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, ITokenRepository tokenRepository,IMapper mapper)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _tokenRepository = tokenRepository;
            _mapper = mapper;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestModel registerModel)
        {
            if (registerModel == null) return new StatusCodeResult(500);

            ApplicationUser user = await _userManager.FindByNameAsync(registerModel.UserName);

            if (user != null) return BadRequest("User name already exists");

            user = await _userManager.FindByEmailAsync(registerModel.Email);

            if (user != null) return BadRequest("Email already exists");

            if (registerModel.Password != registerModel.ConfirmPassword) return BadRequest("Password not match");

            var now = DateTime.Now;

            user = new ApplicationUser()
            {
                Id = Guid.NewGuid().ToString(),
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerModel.UserName,
                Email = registerModel.Email,
                EmailConfirmed = true,
                LockoutEnabled = false,
                CreatedDate = now,
                DisplayName = registerModel.DisplayName
            };

            var passwordErros = ValidatePassword(registerModel.Password);

            if (passwordErros.Result != null) return BadRequest(passwordErros);

            try
            {
                var result = await _userManager.CreateAsync(user, registerModel.Password);
            }
            catch (Exception)
            {
                return new UnprocessableEntityResult();
            }

            //Create Roles (if they doesn't exist yet)
            if (!await _roleManager.RoleExistsAsync(UserRoles.RegisteredUser))
            {
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.RegisteredUser));
            }

            //Add Role
            if (await _roleManager.RoleExistsAsync(UserRoles.RegisteredUser)){
                await _userManager.AddToRoleAsync(user,UserRoles.RegisteredUser);
            }

            var response = _mapper.Map<ApplicationUserResponseModel>(user);
            return Json(response);
        }

        [HttpPost]
        [Route("RegisterAdmin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterRequestModel registerModel)
        {
            if (registerModel == null) return new StatusCodeResult(500);

            ApplicationUser user = await _userManager.FindByNameAsync(registerModel.UserName);

            if (user != null) return BadRequest("User name already exists");

            user = await _userManager.FindByEmailAsync(registerModel.Email);

            if (user != null) return BadRequest("Email already exists");

            if (registerModel.Password != registerModel.ConfirmPassword) return BadRequest("Password not match");

            var now = DateTime.Now;

            user = new ApplicationUser()
            {
                Id = Guid.NewGuid().ToString(),
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerModel.UserName,
                Email = registerModel.Email,
                EmailConfirmed = true,
                LockoutEnabled = false,
                CreatedDate = now,
                DisplayName = registerModel.DisplayName
            };

            var passwordErros = ValidatePassword(registerModel.Password);

            if (passwordErros.Result != null) return BadRequest(passwordErros);

            try
            {
                var result = await _userManager.CreateAsync(user, registerModel.Password);
            }
            catch (Exception)
            {
                return new UnprocessableEntityResult();
            }

            //Create Roles (if they doesn't exist yet)
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            }

            //Add Role
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }

            var response = _mapper.Map<ApplicationUserResponseModel>(user);
            return Json(response);
        }

        [HttpPost]
        [Route("Auth")]
        public async Task<IActionResult> Jwt([FromBody] TokenRequestModel requestModel)
        {
            // return a generic HTTP Status 500 (Server Error)
            // if the client payload is invalid.
            if (requestModel == null) return new StatusCodeResult(500);

            return requestModel.grant_type switch
            {
                "password" => await GetTokenAsync(requestModel),
                "refresh_token" => await RefreshAccessTokenAsync(requestModel),
                "sign_out" => await SignOutAsync(),
                _ => new UnauthorizedResult()
            };
        }

        private async Task<IActionResult> SignOutAsync()
        {
            await HttpContext.SignOutAsync();
            return Ok();
        }

        private async Task<IActionResult> RefreshAccessTokenAsync(TokenRequestModel model)
        {
            try
            {
                var refreshToken = await _tokenRepository.FindByKeysAsync(model.provider_id, model.refresh_token);

                if (refreshToken == null)
                {
                    return new UnauthorizedResult();
                }

                var user = await _userManager.FindByIdAsync(refreshToken.UserId);

                if (user == null)
                {
                    return new UnauthorizedResult();
                }

                var newRefreshToken = CreateRefreshToken(refreshToken.LoginProvider, refreshToken.UserId, user.UserName);

                await _tokenRepository.RemoveAsync(refreshToken);
                await _tokenRepository.AddAsync(newRefreshToken);

                var token = CreateAccessToken(user, newRefreshToken.Value);

                return Json(token);
            }
            catch (Exception)
            {
                return new UnauthorizedResult();
            }
        }

        private async Task<IActionResult> GetTokenAsync(TokenRequestModel model)
        {
            try
            {
                // check if there's an user with the given username
                var user = await _userManager.FindByNameAsync(model.username);

                // fallback to support e-mail address instead of username
                if (user == null && model.username.Contains("@"))
                    user = await
                        _userManager.FindByEmailAsync(model.username);

                if (user == null
                   || !await _userManager.CheckPasswordAsync(user,
                       model.password))
                {
                    // user does not exists or password mismatch
                    return new UnauthorizedResult();
                }

                // username & password matches: create the refresh token
                var refreshToken = CreateRefreshToken(model.provider_id, user.Id, model.username);

                // delete user token if it is exist in DB  (appropriate refreshToken)
                await _tokenRepository.RemoveAsync(new ApplicationUserToken()
                {
                    LoginProvider = model.provider_id,
                    UserId = user.Id.ToString(),
                    Name = model.username
                });

                // add the new refresh token to the DB (appropriate refreshToken )
                await _tokenRepository.AddAsync(refreshToken);

                //Get Access Token
                var token = CreateAccessToken(user, refreshToken.Value);

                return Json(token);

            }
            catch (Exception ex)
            {
                return new UnauthorizedResult();
            }
        }

        private ApplicationUserToken CreateRefreshToken(string clientId, string userId, string name)
        {
            return new ApplicationUserToken()
            {
                LoginProvider = clientId,
                UserId = userId,
                Name = name,
                Type = 0,
                Value = Guid.NewGuid().ToString("N"),
                AddedDate = DateTime.UtcNow
            };
        }

        private TokenResponseModel CreateAccessToken(ApplicationUser user, string refreshToken)
        {
            var now = DateTime.UtcNow;

            // add the registered claims for JWT (RFC7519).
            // For more info, see https://tools.ietf.org/html/rfc7519#section-4.1
            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString()),
				// TODO: add additional claims here
            };

            var userRoles = _userManager.GetRolesAsync(user);
            var roles = userRoles.GetAwaiter().GetResult();

            if (roles != null && roles.Count > 0)
            {
                claims.AddRange(roles.Select(x => new Claim(ClaimTypes.Role, x)));
            }

            var tokenExpirationMins = _configuration.GetValue<int>("Auth:Jwt:TokenExpirationInMinutes");
            var issuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Auth:Jwt:Key"]));

            var token = new JwtSecurityToken(
               issuer: _configuration["Auth:Jwt:Issuer"],
                audience: _configuration["Auth:Jwt:Audience"],
                claims: claims.ToArray(),
                notBefore: now,
                expires: now.Add(TimeSpan.FromMinutes(tokenExpirationMins)),
                 signingCredentials: new SigningCredentials(
                    issuerSigningKey, SecurityAlgorithms.HmacSha256)
                );

            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);

            return new TokenResponseModel()
            {
                token = encodedToken,
                expiration = tokenExpirationMins,
                refresh_token = refreshToken
            };
        }

        private async Task<string> ValidatePassword(string password)
        {
            List<string> passwordErrors = new List<string>();

            var validators = _userManager.PasswordValidators;

            foreach (var validator in validators)
            {
                var validation = await validator.ValidateAsync(_userManager, null, password);

                if (!validation.Succeeded)
                {
                    foreach (var error in validation.Errors)
                    {
                        passwordErrors.Add(error.Description);
                    }
                }
            }

            var result = passwordErrors.Count > 0 ? passwordErrors.Aggregate((i, j) => i + "\n" + j) : null;

            return result;
        }
    }
}