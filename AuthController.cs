using System.Text;
using Application.Helpers;
using Application.Interfaces.Services;
using AutoWrapper.Wrappers;
using Domain.Dtos;
using Domain.Dtos.IdentityDto;
using Domain.EntityModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Shared.Constants;
using WebApi.Controllers.Base;

namespace WebApi.Controllers;
[ApiController]
[Route("api/[controller]")]
[Authorize]
public sealed class AuthController : ControllerBase
{
    private readonly UserManager<UserEntity> _userManager;
    private readonly SignInManager<UserEntity> _signInManager;
    private readonly IJwtTokenProvider _jwtTokenProvider;
    private readonly MailHelper _mailHelper;

    public AuthController(UserManager<UserEntity> userManager, IJwtTokenProvider jwtTokenProvider,
        SignInManager<UserEntity> signInManager,
        MailHelper mailHelper) : base(userManager)
    {
        _userManager = userManager;
        _jwtTokenProvider = jwtTokenProvider;
        _signInManager = signInManager;
        _mailHelper = mailHelper;
    }


    [AllowAnonymous]
    [HttpPost("Login")]
    public async Task<ApiResponse> Login(LoginDto dto, CancellationToken cancellationToken)
    {
        UserEntity? user;
        if (dto.Email.Equals("admin@pk.com"))
        {
            user = await _userManager.Users.FirstOrDefaultAsync(x => x.Email!.Equals(dto.Email), cancellationToken);
        }
        else
        {
            user = await _userManager.FindByEmailAsync(dto.Email);
        }

        if (user is null)
        {
            return CreateApiResponse(true, $"No user exist with this email {dto.Email}", ApiCode.NoContent);
        }

        if (!await _userManager.IsEmailConfirmedAsync(user))
            return CreateApiResponse(true, "Account not verified please confirm your account and retry to login",
                ApiCode.BadRequest);
        var isWrongPassword = await _userManager.CheckPasswordAsync(user, dto.Password);
        if (!isWrongPassword)
            return CreateApiResponse(true, "Password is not matched!", ApiCode.BadRequest);
        var checkTwoStep = await _userManager.GetTwoFactorEnabledAsync(user);
        var roles = await _userManager.GetRolesAsync(user);
        var token = await GetTokenForUser(dto, cancellationToken, user, roles);
        if (checkTwoStep)
        {
            return CreateApiResponse(false, "Request Processed", ApiCode.Success,
                new LoginResponseDto(true, token));
        }

        return CreateApiResponse(false, "Login successfully!", ApiCode.Success, new LoginResponseDto(false, token));
    }

    private async Task<string> GetTokenForUser(LoginDto dto, CancellationToken cancellationToken, UserEntity user,
        IList<string> roles)
    {
        var token = await _jwtTokenProvider.GetJwtToken(
            new(dto.Email, dto.Password, user.Id, user.InstitutionId, $"{user.FirstName} {user.LastName}",
                user.InstituteName, roles.First()), cancellationToken);
        return token;
    }

    [HttpPost(nameof(Verify2Fa))]
    public async Task<ApiResponse> Verify2Fa([FromForm] string code)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user != null)
        {
            var isCodeMatched = await _userManager.VerifyTwoFactorTokenAsync(user, "Authenticator", code);
            if (!isCodeMatched)
            {
                return CreateApiResponse(true, "Code not matched!", ApiCode.BadRequest);
            }
        }
        else
        {
            return CreateApiResponse(true, "No user exist", ApiCode.NoContent);
        }

        return CreateApiResponse(false, "Code Matched", ApiCode.Success);
    }

    [HttpGet(nameof(Enable2Fa))]
    public async Task<ApiResponse> Enable2Fa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
            return CreateApiResponse(true, "No user exist", ApiCode.NoContent);
        var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (authenticatorKey == null)
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        return CreateApiResponse(false, "Request Processed!", ApiCode.Success, authenticatorKey);
    }

    [HttpPost(nameof(Enable2Fa))]
    public async Task<ApiResponse> Enable2Fa([FromForm] string code)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return CreateApiResponse(true, "No user exist", ApiCode.NoContent);
        }

        bool isValidCode = await _userManager.VerifyTwoFactorTokenAsync(user!,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            code);

        if (isValidCode)
        {
            await _userManager.SetTwoFactorEnabledAsync(user!, true);
        }
        else
        {
            return CreateApiResponse(true, "Invalid code", ApiCode.BadRequest);
        }

        return CreateApiResponse(false, "Request Processed!", ApiCode.Success);
    }

    [HttpPut(nameof(Disable2Fa))]
    public async Task<ApiResponse> Disable2Fa([FromForm] string password)
    {
        var user = await _userManager.GetUserAsync(User);
        var signInResult = await _signInManager.CheckPasswordSignInAsync(user!, password, false);
        if (!signInResult.Succeeded)
            return CreateApiResponse(true, "Password is not matched!", ApiCode.BadRequest);

        user!.TwoFactorEnabled = false;
        await _userManager.UpdateAsync(user);
        return CreateApiResponse(string.Empty);
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<ApiResponse> ForgotPassword(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
            return CreateApiResponse("User Does not exist with email: " + email, ApiCode.NoContent);
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = Encoding.UTF8.GetBytes(token);
        var validToken = WebEncoders.Base64UrlEncode(encodedToken);
        //var baseUrl = _configuration["CloudUrl:DMSWeb"]!;
        //var callbackUrl = $"{baseUrl}/auth/reset-password?email={email}&token={validToken}";
        var callbackUrl = $"http://localhost:3000/ResetPassword?email={email}&token={validToken}";
        var emailRequest = MakeEmailRequest(email, user, callbackUrl);
        var response = await _mailHelper.SendMailBySendGrid(emailRequest);
        if (response.IsSuccessStatusCode)
            return CreateApiResponse("Email send successfully");
        return Error("Something went wrong");
    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<ApiResponse> ResetPassword(ResetPasswordRequestDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null) return CreateApiResponse("User Does not exist with email: " + model.Email, ApiCode.NoContent);
        if (model.NewPassword != model.ConfirmPassword)
            return CreateApiResponse("Password does not match", ApiCode.BadRequest);
        var decodedToken = WebEncoders.Base64UrlDecode(model.Token);
        var normalToken = Encoding.UTF8.GetString(decodedToken);
        var result = await _userManager.ResetPasswordAsync(user, normalToken, model.NewPassword);
        if (result.Succeeded)
            return CreateApiResponse("Password reset successfully");
        return Error(result.Errors);
    }

    [HttpGet(nameof(UserImpersonate))]
    [AllowAnonymous]
    public async Task<ApiResponse> UserImpersonate(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user is null)
            return CreateApiResponse("User Does not exist!", ApiCode.NoContent);
        var roles = await _userManager.GetRolesAsync(user);
        var token = await _jwtTokenProvider.GetJwtToken(
            new(user.Email!, string.Empty, user.Id, user.InstitutionId, $"{user.FirstName} {user.LastName}",
                user.InstituteName, roles.First()), CancellationToken.None);
        return CreateApiResponse(false, $"Login successfully!", ApiCode.Success, token);
    }

    private static MailRequestDto MakeEmailRequest(string email, UserEntity user, string callbackUrl)
    {
        return new MailRequestDto
        {
            ToEmail = email,
            Subject = "BrightFit Account: Password Reset Request",
            Body = EmailTemplates.ForgotPasswordTemplate($"{user.FirstName} {user.LastName}", callbackUrl)
        };
    }

    [AllowAnonymous]
    [HttpPut("VerifyAccountEmail")]
    public async Task<ApiResponse> VerifyAccountEmail(ConfirmEmailDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return CreateErrorApiResponse($"No user exist with this email {request.Email}", ApiCode.NoContent);
        var result = await _userManager.ConfirmEmailAsync(user, request.Token);
        if (result.Succeeded)
        {
            await SendWelcomeEmail(user!.Email!, $"{user.FirstName} {user.LastName}");
            return CreateApiResponse("Email confirmed successfully");
        }

        return Error(result.Errors);
    }

    private async Task SendWelcomeEmail(string userEmail, string userName)
    {
        var mailRequest = new MailRequestDto
        {
            ToEmail = userEmail,
            Subject = $"Welcome to BrightFit, {userName}!",
            Body = EmailTemplates.WelcomeEmailTemplate(userName)
        };
        var response = await _mailHelper.SendMailBySendGrid(mailRequest);
    }
}
