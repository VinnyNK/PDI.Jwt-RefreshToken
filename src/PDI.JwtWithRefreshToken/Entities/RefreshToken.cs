namespace PDI.JwtWithRefreshToken.Entities;

public class RefreshToken
{
    public Guid Id { get; set; }

    public string? Token { get; set; }
}