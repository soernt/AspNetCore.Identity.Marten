namespace Marten.AspNetCore.Identity.Models;

/// <summary>
/// A class representing a claim.
/// </summary>
public class MartenIdentityClaim
{
    /// <summary>
    /// The type of the claim.
    /// </summary>
    public virtual string Type { get; set; }

    /// <summary>
    /// The value of the claim.
    /// </summary>
    public virtual string Value { get; set; }

    /// <summary>
    /// The issuer of the claim.
    /// </summary>
    public virtual string Issuer { get; set; }

    /// <summary>
    /// Constructs a new instance of <see cref="MartenIdentityClaim"/>
    /// </summary>
    public MartenIdentityClaim()
    {
        Type = string.Empty;
        Value = string.Empty;
        Issuer = string.Empty;
    }

    private sealed class TypeValueIssuerEqualityComparer : IEqualityComparer<MartenIdentityClaim>
    {
        public bool Equals(MartenIdentityClaim? x, MartenIdentityClaim? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (ReferenceEquals(x, null)) return false;
            if (ReferenceEquals(y, null)) return false;
            if (x.GetType() != y.GetType()) return false;
            return string.Equals(x.Type, y.Type, StringComparison.Ordinal)
                   && string.Equals(x.Value, y.Value, StringComparison.Ordinal)
                   && string.Equals(x.Issuer, y.Issuer, StringComparison.Ordinal);
        }

        public int GetHashCode(MartenIdentityClaim obj)
        {
            return HashCode.Combine(obj.Type, obj.Value, obj.Issuer);
        }
    }

    /// <summary>
    /// Creates and IEqualityComparer{MartenIdentityClaim} which considers the
    ///  Type, Value and Issuer properties.
    /// </summary>
    public static IEqualityComparer<MartenIdentityClaim> TypeAndValueAndIssuerComparer { get; } =
        new TypeValueIssuerEqualityComparer();
}