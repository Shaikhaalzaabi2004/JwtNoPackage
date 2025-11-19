using JwtNoPackage.Models;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JwtNoPackage.Controllers
{
    [ApiController]
    [Route("api")]
    public class WeatherForecastController : ControllerBase
    {
        TokenService tokenService = new TokenService();
        JwtDatabaseContext _db = new JwtDatabaseContext();
        public string HashData(string data)
        {
            var hashedBytes = SHA512.HashData(Encoding.UTF8.GetBytes(data));
            return Convert.ToBase64String(hashedBytes);
        }

        public async Task<TokenDTO?> IsAuthorized(HttpRequest httpRequest) 
        {
            if(!httpRequest.Headers.ContainsKey("Authorization"))
                return null;

            var token = httpRequest.Headers.Authorization.ToString()["Bearer ".Length..];

            var decodedResult = await tokenService.DecodeToken(token);
            if(decodedResult == null) return null;

            return decodedResult;
        }

        [HttpPost("login")]
        public async Task<ActionResult> Login(Models.LoginRequest loginRequest)
        {
            var user = _db.Users.FirstOrDefault(x=> x.Email == loginRequest.Email && x.Password == HashData(loginRequest.Password));

            if (user == null) return NotFound("Invalid Credentials");

            if (!user.IsVerified) return Unauthorized("Verify Email");

            var token = tokenService.GenerateToken(user.Id, user.RoleId);
            return Ok(token);
        }

        [HttpPost("register")]
        public async Task<ActionResult> Register(User user)
        {
            var tokenInfo = await IsAuthorized(Request);
            if (tokenInfo == null)
                return Unauthorized();

            var userToAuth = _db.Users.FirstOrDefault(x=> x.Id == tokenInfo.UserId);

            if (userToAuth.RoleId != 1) return Unauthorized("Only Admins Can Register Users");

            user.Password = HashData(user.Password);
            _db.Users.Add(user);
            _db.SaveChanges();

            await tokenService.SendMailAsync(user);
            return Ok("User Registered, Verify Email To Proceed");
        }

        [HttpGet("verify-email")]
        public async Task<ActionResult> Verify(string token)
        {
            var tokenInfo = await tokenService.DecodeToken(token);
            if(tokenInfo == null) return Unauthorized("Invalid Token");

            var userToAuth = _db.Users.FirstOrDefault(x => x.Id == tokenInfo.UserId);
            userToAuth.IsVerified = true;
            _db.SaveChanges();

            return Ok("Email Verified");
        }

        [HttpGet("profile")]
        public async Task<ActionResult> ViewProfile()
        {
            var tokenInfo = await IsAuthorized(Request);
            if (tokenInfo == null)
                return Unauthorized();

            var userToView = _db.Users.FirstOrDefault(x => x.Id == tokenInfo.UserId);
            return Ok(userToView);
        }
    }
}
