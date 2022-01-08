using Marten.AspNetCore.Identity.Models;
using Microsoft.AspNetCore.Identity;

namespace Marten.AspNetCore.Identity.Extensions;

/// <summary>
/// Extensions around the <see cref="MartenIdentityUserLogin"/> class
/// </summary>
public static class MartenIdentityUserLoginExtensions
{
    public static MartenIdentityUserLogin ToMartenIdentityUserLogin(this UserLoginInfo login)
    {
        return new MartenIdentityUserLogin
        {
            ProviderKey = login.ProviderKey,
            LoginProvider = login.LoginProvider,
            ProviderDisplayName = login.ProviderDisplayName,
        };   
    }

    public static UserLoginInfo ToUserLoginInfo(this MartenIdentityUserLogin login)
    {
        return new UserLoginInfo(login.LoginProvider, login.ProviderKey, login.ProviderDisplayName);
    }
}