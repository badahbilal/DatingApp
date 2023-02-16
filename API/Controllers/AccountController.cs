using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")] // POST: api/account/register
                               // POST: /api/account/register?username=sam&password=password
                               //       This method allow ApiController to bind the username and password
                               //       From the request url to action parameters
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {

            // When we use [ApiController] we don't need to bind the username and password
            // and we don't need to check if the username and password are valid
            // because ApiController will check if the username and password are valid
            // and if the username and password are valid we can bind the username and password
            // also we don't neet to use FromBody method to bind data comming from the request
            // if(ModelState.IsValid){

            // }

            if (await ValidateUser(registerDto.username))
            {
                return BadRequest("Username is already registered");
            }

            using var hmac = new HMACSHA256();

            var user = new AppUser
            {
                UserName = registerDto.username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x =>
                    x.UserName.ToLower() == loginDto.UserName.ToLower());

            if (user == null)
                return Unauthorized("invalid username");

            using var hmac = new HMACSHA256(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> ValidateUser(string usenamer)
        {
            return await _context.Users.AnyAsync(x => x.UserName == usenamer.ToLower());
        }

    }
}