using System.Security.Claims;
using Marten.AspNetCore.Identity.Models;

namespace Marten.AspNetCore.Identity.Extensions;

/// <summary>
/// Extensions regarding to <see cref="MartenIdentityClaim"/> and <see cref="Claim"/>
/// </summary>
public static class MartenIdentityClaimExtensions
{
    /// <summary>
    /// Creates an <see cref="Claim"/> instance based on a <see cref="MartenIdentityClaim"/> 
    /// </summary>
    /// <param name="martenIdentityClaim"></param>
    /// <returns></returns>
    public static Claim ToClaim(this MartenIdentityClaim martenIdentityClaim)
    {
        return new Claim(martenIdentityClaim.Type, martenIdentityClaim.Value, null, martenIdentityClaim.Issuer);
    }

    /// <summary>
    /// Creates as <see cref="MartenIdentityClaim"/> to a <see cref="Claim"/>
    /// </summary>
    /// <param name="claim"></param>
    /// <returns></returns>
    public static MartenIdentityClaim ToMartenIdentityClaim(this Claim claim)
    {
        return new MartenIdentityClaim
        {
            Type = claim.Type,
            Value = claim.Value,
            Issuer = claim.Issuer,
        };
    }
}