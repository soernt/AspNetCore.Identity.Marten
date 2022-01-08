namespace Marten.AspNetCore.Identity.Models;

/// <summary>
/// A class representing a recovery code (User Two Factor Recovery.)
/// </summary>
public class MartenIdentityRecoveryCode
{
    public string Code { get; set; }

    public MartenIdentityRecoveryCode()
    {
        Code = string.Empty;
    }

    public MartenIdentityRecoveryCode(string code)
    {
        Code = code;
    }


    private sealed class CodeEqualityComparer : IEqualityComparer<MartenIdentityRecoveryCode>
    {
        public bool Equals(MartenIdentityRecoveryCode? x, MartenIdentityRecoveryCode? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (ReferenceEquals(x, null)) return false;
            if (ReferenceEquals(y, null)) return false;
            return x.GetType() == y.GetType()
                   && string.Equals(x.Code, y.Code, StringComparison.Ordinal);
        }

        public int GetHashCode(MartenIdentityRecoveryCode obj)
        {
            return StringComparer.Ordinal.GetHashCode(obj.Code);
        }
    }

    /// <summary>
    /// Comparer for <see cref="MartenIdentityRecoveryCode"/> which considers the Code property
    /// </summary>
    public static IEqualityComparer<MartenIdentityRecoveryCode> CodeComparer { get; } = new CodeEqualityComparer();
}