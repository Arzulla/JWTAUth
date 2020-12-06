using Newtonsoft.Json;

namespace JWTAuth.Models.ResponseModel
{
    [JsonObject(MemberSerialization.OptOut)]
    public class TokenResponseModel
    {
        public string token { get; set; }

        public int expiration { get; set; }

        public string refresh_token { get; set; }
    }
}
