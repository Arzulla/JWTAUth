using JWTAuth.Models.Identity;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuth.Repository
{
    public interface ITokenRepository
    {
        Task AddAsync(ApplicationUserToken applicationUserToken);

        Task<ApplicationUserToken> FindByKeysAsync(string loginProvider, string refreshToken);

        Task RemoveAsync(ApplicationUserToken applicationUserToken);

        Task RemoveByRefreshTokenAsync(string refreshToken);
    }
    public class TokenRepository : ITokenRepository
    {
        private readonly ApplicationDbContext _context;

        public TokenRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task AddAsync(ApplicationUserToken applicationUserToken)
        {
            _context.ApplicationUserTokens.Add(applicationUserToken);

            await _context.SaveChangesAsync();
        }

        public async Task<ApplicationUserToken> FindByKeysAsync(string loginProvider, string refreshToken)
        {
            var result = _context.ApplicationUserTokens.FirstOrDefault<ApplicationUserToken>(x => x.LoginProvider == loginProvider && x.Value == refreshToken);

            await _context.SaveChangesAsync();

            return result;
        }

        public async Task RemoveAsync(ApplicationUserToken applicationUserToken)
        {
            ApplicationUserToken entity = _context.ApplicationUserTokens.FirstOrDefault<ApplicationUserToken>(x => x.LoginProvider == applicationUserToken.LoginProvider && x.UserId == applicationUserToken.UserId && x.Name == applicationUserToken.Name);

            if(entity!=null)
            _context.Remove(entity);

            await _context.SaveChangesAsync();
        }

        public async Task RemoveByRefreshTokenAsync(string refreshToken)
        {
            var appUserToken = _context.ApplicationUserTokens.FirstOrDefault<ApplicationUserToken>(x => x.Value == refreshToken);

            _context.Remove(appUserToken);

            await _context.SaveChangesAsync();
        }
    }
}
