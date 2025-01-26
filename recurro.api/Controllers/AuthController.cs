using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using recurro.api.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace recurro.api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<UserModel> _userManager;
    private readonly SignInManager<UserModel> _signInManager;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<UserModel> userManager, SignInManager<UserModel> signInManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    // Hide this endpoint from the Swagger UI for unauthorized users
    [ApiExplorerSettings(IgnoreApi = true)]
    public IActionResult AdminOnlyEndpoint()
    {
        return Ok("This endpoint is restricted to admin users.");
    }

    [HttpGet("user-only")]
    [Authorize(Roles = "Admin, User")]
    [ApiExplorerSettings(IgnoreApi = true)]
    public IActionResult UserOnlyEndpoint()
    {
        return Ok("This endpoint is restricted to regular users.");
    }

    // No Email confirmation for now
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var user = new UserModel { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            // Assign the "User" role to the newly registered user
            await _userManager.AddToRoleAsync(user, "User");
            return Ok(new { Message = "User registered successfully" });
        }

        return BadRequest(result.Errors);
    }


    // Email confirmation registration - not implemented yet
    // [HttpPost("register")]
    // public async Task<IActionResult> Register([FromBody] RegisterModel model)
    // {
    //     var user = new UserModel { UserName = model.Username, Email = model.Email };
    //     var result = await _userManager.CreateAsync(user, model.Password);

    //     if (result.Succeeded)
    //     {
    //         var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
    //         var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", new { token, email = user.Email }, Request.Scheme);
    //         // Here you would send the confirmation link to the user's email. For simplicity, we'll return it in the response.
    //         return Ok(new { Message = "User registered successfully", ConfirmationLink = confirmationLink });
    //     }

    //     return BadRequest(result.Errors);
    // }

    // [HttpGet("confirm-email")]
    // public async Task<IActionResult> ConfirmEmail(string token, string email)
    // {
    //     var user = await _userManager.FindByEmailAsync(email);
    //     if (user == null)
    //     {
    //         return BadRequest("User not found.");
    //     }

    //     var result = await _userManager.ConfirmEmailAsync(user, token);
    //     if (result.Succeeded)
    //     {
    //         return Ok(new { Message = "Email confirmed successfully" });
    //     }

    //     return BadRequest(result.Errors);
    // }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);
        if (user == null)
        {
            return Unauthorized("Invalid username or password.");
        }

        var result = await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            return Unauthorized("Invalid username or password.");
        }

        var token = GenerateJwtToken(user);
        return Ok(new { Token = token });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok(new { Message = "User logged out successfully" });
    }


    // Password reset - not implemented yet
    // [HttpPost("request-password-reset")]
    // public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestModel model)
    // {
    //     var user = await _userManager.FindByEmailAsync(model.Email);
    //     if (user == null)
    //     {
    //         return BadRequest("User not found.");
    //     }

    //     var token = await _userManager.GeneratePasswordResetTokenAsync(user);
    //     // Here you would send the token to the user's email. For simplicity, we'll return it in the response.
    //     return Ok(new { Token = token });
    // }

    // [HttpPost("reset-password")]
    // public async Task<IActionResult> ResetPassword([FromBody] PasswordResetModel model)
    // {
    //     var user = await _userManager.FindByEmailAsync(model.Email);
    //     if (user == null)
    //     {
    //         return BadRequest("User not found.");
    //     }

    //     var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
    //     if (result.Succeeded)
    //     {
    //         return Ok(new { Message = "Password reset successfully" });
    //     }

    //     return BadRequest(result.Errors);
    // }


    private string GenerateJwtToken(UserModel user)
    {
        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? string.Empty),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

        var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? "YourSecretKeyHere";
        if (string.IsNullOrEmpty(jwtKey))
        {
            throw new InvalidOperationException("JWT Key is not configured.");
        }
        Console.WriteLine("Using JWT_KEY for token generation: " + jwtKey);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

