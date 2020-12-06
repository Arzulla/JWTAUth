using AutoMapper;
using JWTAuth.Models.Identity;
using JWTAuth.Models.ResponseModel;

namespace JWTAuth.Infrastructure.Mappers
{
    public class ApplicationUserProfile : Profile
    {
        public ApplicationUserProfile()
        {
            CreateMap<ApplicationUser, ApplicationUserResponseModel>();
        }
    }
}
