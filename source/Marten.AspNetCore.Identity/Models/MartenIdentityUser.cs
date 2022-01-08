using Marten.Metadata;

namespace Marten.AspNetCore.Identity.Models;

/// <summary>
/// A document representing an <see cref="MartenIdentityUser"/> document.
/// </summary>
public class MartenIdentityUser : IVersioned
{
    /// <summary>
    /// Gets or sets the primary key of this user.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// This is Marten default Optimistic concurrency property. 
    /// </summary>
    public Guid Version { get; set; }

    /// <summary>
    /// The user name
    /// </summary>
    public string UserName { get; set; }

    /// <summary>
    /// The normalized user name, maintained by the Identity framework 
    /// </summary>
    public string NormalizedUserName { get; set; }

    /// <summary>
    /// The EMail
    /// </summary>
    public string EmailAddress { get; set; }

    /// <summary>
    /// The normalized email, maintained by the Identity framework
    /// </summary>
    public string NormalizedEmailAddress { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating if a user has confirmed their email address.
    /// </summary>
    /// <value>True if the email address has been confirmed, otherwise false.</value>
    public bool IsEmailConfirmed { get; set; }

    /// <summary>
    /// The password hash, maintained by the Identity framework
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// A random value that must change whenever a users credentials change (password changed, login removed)
    /// </summary>
    public string SecurityStamp { get; set; }

    /// <summary>
    /// The phone number
    /// </summary>
    public string PhoneNumber { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating if a user has confirmed their telephone address.
    /// </summary>
    /// <value>True if the telephone number has been confirmed, otherwise false.</value>
    public bool IsPhoneNumberConfirmed { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating if two factor authentication is enabled for this user.
    /// </summary>
    /// <value>True if 2fa is enabled, otherwise false.</value>
    public bool IsTwoFactorEnabled { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating if the user could be locked out.
    /// </summary>
    /// <value>True if the user could be locked out, otherwise false.</value>
    public bool IsLockoutEnabled { get; set; }

    /// <summary>
    /// Gets or sets the date and time, in UTC, when any user lockout ends.
    /// </summary>
    /// <remarks>
    /// A value in the past means the user is not locked out.
    /// </remarks>
    public DateTimeOffset? LockoutEndAtUtc { get; set; }

    /// <summary>
    /// Gets or sets the number of failed login attempts for the current user.
    /// </summary>
    public int AccessFailedCount { get; set; }

    /// <summary>
    /// The roles this user belongs to.
    /// </summary>
    public HashSet<MartenIdentityRole> Roles { get; set; }

    /// <summary>
    /// The claims this user has been assigned.
    /// Note: Roles also have claims. The claims of the roles are not enlisted within the claims.
    /// </summary>
    public HashSet<MartenIdentityClaim> Claims { get; set; }

    /// <summary>
    /// The different logins the user has. Also external logins from social media ...
    /// </summary>
    public HashSet<MartenIdentityUserLogin> Logins { get; set; }

    /// <summary>
    /// The tokens per provider and name.
    /// </summary>
    public HashSet<MartenIdentityUserToken> Tokens { get; set; }

    /// <summary>
    /// Recovery tokens used by two factory authentication. 
    /// </summary>
    public HashSet<MartenIdentityRecoveryCode> RecoveryCodes { get; set; }

    /// <summary>
    /// Creates an instance of <see cref="MartenIdentityUser"/>
    /// </summary>
    public MartenIdentityUser()
    {
        UserName = string.Empty;
        NormalizedUserName = string.Empty;
        EmailAddress = string.Empty;
        NormalizedEmailAddress = string.Empty;
        PasswordHash = null;
        SecurityStamp = string.Empty;
        PhoneNumber = string.Empty;

        Roles = new HashSet<MartenIdentityRole>(MartenIdentityRole.NameComparer);
        Claims = new HashSet<MartenIdentityClaim>(MartenIdentityClaim.TypeAndValueAndIssuerComparer);
        Logins = new HashSet<MartenIdentityUserLogin>(MartenIdentityUserLogin.LoginProviderAndProviderKeyComparer);
        Tokens = new HashSet<MartenIdentityUserToken>(MartenIdentityUserToken.LoginProviderAndNameComparer);
        RecoveryCodes = new HashSet<MartenIdentityRecoveryCode>(MartenIdentityRecoveryCode.CodeComparer);
    }

    /// <summary>
    /// Equals is based on Id and Version
    /// Need to override Equal in order to pass the MS Tests 
    /// </summary>
    /// <param name="obj"></param>
    /// <returns></returns>
    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(null, obj))
        {
            return false;
        }

        if (ReferenceEquals(this, obj))
        {
            return true;
        }

        return obj.GetType() == GetType()
               && Id.Equals(((MartenIdentityUser)obj).Id)
               && Version.Equals(((MartenIdentityUser)obj).Version);
    }

    /// <summary>
    /// Equals is based on Id and Version
    /// Need to override Equal in order to pass the MS Tests 
    /// </summary>
    /// <returns></returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(Id, Version);
    }
}