using System;

namespace JWTAuth.Models.ResponseModel
{
    public class ApplicationUserResponseModel
    {
        public Guid Id { get; set; }

        public string DisplayName { get; set; }

        public string UserName { get; set; }

        public string Email { get; set; }
    }
}
