using Microsoft.AspNetCore.Identity;

namespace Marten.AspNetCore.Identity.Models;

/// <summary>
/// Represents an authentication token for a user.
/// </summary>
public class MartenIdentityUserToken
{
    /// <summary>
    /// Gets or sets the LoginProvider this token is from.
    /// </summary>
    public virtual string LoginProvider { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the name of the token.
    /// </summary>
    public virtual string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the token value.
    /// </summary>
    [ProtectedPersonalData]
    public virtual string Value { get; set; } = string.Empty;

    private sealed class LoginProviderNameEqualityComparer : IEqualityComparer<MartenIdentityUserToken>
    {
        public bool Equals(MartenIdentityUserToken? x, MartenIdentityUserToken? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (ReferenceEquals(x, null)) return false;
            if (ReferenceEquals(y, null)) return false;
            if (x.GetType() != y.GetType()) return false;
            return string.Equals(x.LoginProvider, y.LoginProvider, StringComparison.Ordinal)
                   && string.Equals(x.Name, y.Name, StringComparison.Ordinal);
        }

        public int GetHashCode(MartenIdentityUserToken obj)
        {
            return HashCode.Combine(obj.LoginProvider, obj.Name);
        }
    }

    /// <summary>
    /// Creates an IEqualityComparer{MartenIdentityUserToken} which considers the LoginProvider and Name properties. 
    /// </summary>
    public static IEqualityComparer<MartenIdentityUserToken> LoginProviderAndNameComparer { get; } =
        new LoginProviderNameEqualityComparer();
}