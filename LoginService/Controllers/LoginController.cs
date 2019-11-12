using LoginService.Models;
using LoginService.Repositories;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace LoginService.Controllers
{
    public class LoginController : ApiController
    {
        [HttpPost]
        public HttpResponseMessage Login(User user)
        {
            User u = new UserRepository().GetUser(user.Username);

            if (u == null)
                return Request.CreateResponse(HttpStatusCode.NotFound, "The user was not found.");

            bool credentials = u.Password.Equals(user.Password);

            if (!credentials) return Request.CreateResponse(HttpStatusCode.Forbidden,
                "The username/password combination was wrong.");

            return Request.CreateResponse(HttpStatusCode.OK, new { User = user, Token = TokenManager.GenerateToken(user.Username) });
        }

        [HttpGet]
        [Authorize]
        public HttpResponseMessage Validate(string token, string username)
        {
            bool exists = new UserRepository().GetUser(username) != null;

            if (!exists) return Request.CreateResponse(HttpStatusCode.NotFound, "The user was not found.");

            string tokenUsername = TokenManager.ValidateToken(token);

            if (username.Equals(tokenUsername))
                return Request.CreateResponse(HttpStatusCode.OK);

            return Request.CreateResponse(HttpStatusCode.BadRequest);
        }
    }
}
