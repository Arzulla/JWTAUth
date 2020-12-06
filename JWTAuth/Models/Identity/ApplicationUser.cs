using Microsoft.AspNetCore.Identity;
using System;

namespace JWTAuth.Models.Identity
{
    public class ApplicationUser:IdentityUser
    {
        public string DisplayName { get; set; }

        public DateTime CreatedDate { get; set; }
    }
}
