namespace PDI.JwtWithRefreshToken.DTOs;

public class RefreshTokenRequestDto
{
    public string? RefreshToken { get; set; }

    public string? AccessToken { get; set; }
}