using PDI.JwtWithRefreshToken.Entities;

namespace PDI.JwtWithRefreshToken.Repositories;

public class UserRepository : IUserRepository
{
    private readonly List<User> _users;

    public UserRepository()
    {
        _users = new List<User>()
        {
            new()
            {
                Id = Guid.NewGuid(),
                Name = "User1",
                Email = "user1@gmail.com",
                Password = "123321"
            },
            new()
            {
                Id = Guid.NewGuid(),
                Name = "User2",
                Email = "user2@gmail.com",
                Password = "123321"
            }
        };
    }

    public User? AuthenticateUser(string email, string password)
    {
        return _users.FirstOrDefault(x => x.Email == email && x.Password == password);
    }

    public void AddRefreshToken( User user, RefreshToken refreshToken)
    {
        _users.FirstOrDefault(x => x.Id == user.Id)?.RefreshTokens.Add(refreshToken);
    }

    public User? ValidateRefreshToken(Guid userId, string refreshToken)
    {
        return _users.FirstOrDefault(x => x.Id == userId && x.RefreshTokens.Any(_ => _.Token == refreshToken));
    }
}