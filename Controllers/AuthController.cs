using BCrypt.Net;
using JWT_Token.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Token.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();  //used public static beacause it allows the user variable to be accessed from anywhere.

        private readonly IConfiguration _config;  //IConfiguration class helps to read appsetting.js

        public AuthController(IConfiguration config)
        {
            this._config = config;
        }

        [HttpPost("Register")]
        public ActionResult<User> Register(UserDTO request)
        {
            string passswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password); //install Bcrypt package

            user.Name = request.Name;
            user.PasswordHash = passswordHash;
            return Ok(user);
        }


        [HttpPost("Login")]
        public ActionResult<User> Login(UserDTO request)
        {
            if(request.Name != user.Name)
            {
                return BadRequest("User not found");
            }
            if(!BCrypt.Net.BCrypt.Verify(request.Password,user.PasswordHash))
            {
                return BadRequest("Wrong password");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>             // The Claim class represents a claim, which is a piece of information about the user being  
            {                                                // authenticated or authorized.The Claim class typically takes two parameters:
                new Claim(ClaimTypes.Name, user.Name)       //  the claim type and the claim value.
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes
                (_config.GetSection("AppSettings:Token").Value!));

            var cred =new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
            var token =new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);  //this can also be written as:
            return jwt;                                                 //var handler = new JwtSecurityTokenHandler();
        }                                                               //var jwt = handler.WriteToken(token);  



    }

}
