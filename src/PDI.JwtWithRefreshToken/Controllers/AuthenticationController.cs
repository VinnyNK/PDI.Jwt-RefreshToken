using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using PDI.JwtWithRefreshToken.DTOs;
using PDI.JwtWithRefreshToken.Entities;
using PDI.JwtWithRefreshToken.Repositories;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace PDI.JwtWithRefreshToken.Controllers;

[Route("auth")]
public class AuthenticationController : ControllerBase
{
    private readonly IUserRepository _userRepository;
    private readonly IConfiguration _configuration;

    public AuthenticationController(IConfiguration configuration, IUserRepository userRepository)
    {
        _configuration = configuration;
        _userRepository = userRepository;
    }
    
    
    [HttpPost("Login")]
    public IActionResult Login([FromBody] LoginRequestDto request)
    {
        User? user;
        string refreshToken;
        if (request.GrantsType == GrantType.RefreshToken)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(request.AccessToken);

            var id = Guid.Parse(jwtSecurityToken.Claims.First(x => x.Type == JwtRegisteredClaimNames.Sub).Value);

            user = _userRepository.ValidateRefreshToken(id, request.RefreshToken!);
            refreshToken = request.RefreshToken!;
            
        } else {
            user = _userRepository.AuthenticateUser(request.Email!, request.Password!);
            
            refreshToken = GenerateRefreshToken();
        }
        
        if (user == null)
            return Unauthorized();

        var token = GenerateToken(user.Id, user.Name!, user.Email!);
        
        _userRepository.AddRefreshToken(user, new RefreshToken() { Id = Guid.NewGuid(), Token = refreshToken });
        
        return Ok(new LoginResponseDto()
        {
            AccessToken = token,
            RefreshToken = refreshToken
        });
    }
    
    [HttpGet("Restrict")]
    [Authorize]
    public IActionResult RestrictArea()
    {
        return Ok(new RestricAreaResponseDto()
        {
            Id = HttpContext.User.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.NameIdentifier)?.Value,
            Email = HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
            Name = HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value
        });
    }
    
    private string GenerateToken(Guid id, string name, string email)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.GivenName, name),
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Sub, id.ToString()),
                new Claim(JwtRegisteredClaimNames.Exp, DateTime.UtcNow.AddSeconds(int.Parse(_configuration["JWT:ExpiresIn"])).ToString(CultureInfo.InvariantCulture)),
            }),
            Issuer = _configuration["JWT:ValidIssuer"],
            Audience = _configuration["JWT:ValidAudience"],
            Expires = DateTime.UtcNow.AddSeconds(60),
            SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
            
        };

        var token = new JwtSecurityTokenHandler().CreateToken(tokenDescriptor);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        using var rngCryptoServiceProvider = RandomNumberGenerator.Create();
        var randomBytes = new byte[64];
        rngCryptoServiceProvider.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }
}