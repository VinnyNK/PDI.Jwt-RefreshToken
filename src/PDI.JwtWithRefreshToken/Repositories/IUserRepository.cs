using PDI.JwtWithRefreshToken.Entities;

namespace PDI.JwtWithRefreshToken.Repositories;

public interface IUserRepository
{
    User? AuthenticateUser(string email, string password);

    void AddRefreshToken(User user, RefreshToken refreshToken);

    User? ValidateRefreshToken(Guid userId, string refreshToken);
}