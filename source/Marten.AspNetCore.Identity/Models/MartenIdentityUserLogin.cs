namespace Marten.AspNetCore.Identity.Models;

/// <summary>
/// Represents a login and its associated provider for a user.
/// </summary>
public class MartenIdentityUserLogin
{
    /// <summary>
    /// Gets or sets the login provider for the login (e.g. facebook, google)
    /// </summary>
    public string LoginProvider { get; set; }

    /// <summary>
    /// Gets or sets the unique provider identifier for this login.
    /// </summary>
    public string ProviderKey { get; set; }

    /// <summary>
    /// Gets or sets the friendly name used in a UI for this login.
    /// </summary>
    public string ProviderDisplayName { get; set; }

    /// <summary>
    /// Creates an instance of <see cref="MartenIdentityUserLogin"/>
    /// </summary>
    public MartenIdentityUserLogin()
    {
        LoginProvider = string.Empty;
        ProviderKey = string.Empty;
        ProviderDisplayName = string.Empty;
    }

    private sealed class LoginProviderProviderKeyEqualityComparer : IEqualityComparer<MartenIdentityUserLogin>
    {
        public bool Equals(MartenIdentityUserLogin? x, MartenIdentityUserLogin? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (ReferenceEquals(x, null)) return false;
            if (ReferenceEquals(y, null)) return false;
            if (x.GetType() != y.GetType()) return false;
            return string.Equals(x.LoginProvider, y.LoginProvider, StringComparison.Ordinal)
                   && string.Equals(x.ProviderKey, y.ProviderKey, StringComparison.Ordinal);
        }

        public int GetHashCode(MartenIdentityUserLogin obj)
        {
            return HashCode.Combine(obj.LoginProvider, obj.ProviderKey);
        }
    }

    /// <summary>
    /// Creates an IEqualityComparer{MartenIdentityUserLogin} which considers the
    /// LoginProvider and ProviderKey properties.
    /// </summary>
    public static IEqualityComparer<MartenIdentityUserLogin> LoginProviderAndProviderKeyComparer { get; } =
        new LoginProviderProviderKeyEqualityComparer();
}