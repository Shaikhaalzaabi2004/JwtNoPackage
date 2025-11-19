using JwtNoPackage.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;

namespace JwtNoPackage
{
    public class TokenService
    {
        SymmetricSecurityKey _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("jksdaghjkdhasgfkjhgjkghdjkhgjfdkghjkhfgjhdjkshgjkdsfhgjkfdhgfdk"));
        JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();

        public string GenerateToken(int userId, int roleId) 
        {
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim("userId", userId.ToString()),
                new Claim("roleId", roleId.ToString())
            };

            var token = new JwtSecurityToken(claims: claims, signingCredentials: creds, expires:DateTime.UtcNow.AddMinutes(60));
            return _tokenHandler.WriteToken(token);
        }
        public async Task<TokenDTO?> DecodeToken(string token) 
        {
            var validationParams = new TokenValidationParameters() 
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = _key,
            };

            var result = await _tokenHandler.ValidateTokenAsync(token, validationParams);
            return result.IsValid? new TokenDTO { RoleId = Convert.ToInt32(result.Claims["roleId"]), UserId = Convert.ToInt32(result.Claims["userId"])} : null;
        }

        public async Task SendMailAsync(User user)
        {
            var token = GenerateToken(user.Id, user.RoleId);

            var client = new SmtpClient("localhost", 25)
            {
                Credentials = new NetworkCredential("seoulstay_noreply", "env_qlatLV4G"),
                EnableSsl = false,
                DeliveryMethod = SmtpDeliveryMethod.Network
            };

            var message = new MailMessage("no-reply@mail.seoulstay.kr", user.Email, "Verify Email", $@"<a href=""https://localhost:7120/api/verify-email?token={token}"">click to verify </a>");
            message.IsBodyHtml = true;

            await client.SendMailAsync(message);
        }
    }
}
