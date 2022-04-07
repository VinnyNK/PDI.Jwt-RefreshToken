namespace PDI.JwtWithRefreshToken.DTOs;

public class LoginRequestDto
{
    public string? Email { get; set; }

    public string? Password { get; set; }

    public string? RefreshToken { get; set; }

    public string? AccessToken { get; set; }

    public GrantType GrantsType { get; set; } = GrantType.Password;
}

public enum GrantType
{
    Password = 0,
    RefreshToken = 1        
}