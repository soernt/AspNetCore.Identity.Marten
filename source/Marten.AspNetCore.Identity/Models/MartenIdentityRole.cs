using Marten.Metadata;

namespace Marten.AspNetCore.Identity.Models;

/// <summary>
/// A document representing an <see cref="MartenIdentityRole"/>.
/// </summary>
public class MartenIdentityRole : IVersioned
{
    /// <summary>
    /// Unique identifier
    /// </summary>
    public virtual Guid Id { get; set; }

    /// <summary>
    /// This is Marten default Optimistic concurrency property.
    /// </summary>
    public virtual Guid Version { get; set; }

    /// <summary>
    /// The name of the role
    /// </summary>
    public virtual string Name { get; set; }

    /// <summary>
    /// The normalized name of the role.
    /// Is maintained by the Identity Framework
    /// </summary>
    public virtual string NormalizedName { get; set; }

    /// <summary>
    /// The claims associated to the role
    /// </summary>
    public virtual HashSet<MartenIdentityClaim> Claims { get; set; }

    /// <summary>
    /// Constructs a new instance of <see cref="MartenIdentityRole"/>
    /// </summary>
    public MartenIdentityRole(string name)
    {
        Name = name;
        NormalizedName = string.Empty;
        Claims = new HashSet<MartenIdentityClaim>(MartenIdentityClaim.TypeAndValueAndIssuerComparer);
    }

    public override string ToString()
    {
        return
            $"{nameof(Id)}: {Id}, {nameof(Version)}: {Version}, {nameof(Name)}: {Name}, {nameof(NormalizedName)}: {NormalizedName}, {nameof(Claims)}: {Claims}";
    }

    protected bool Equals(MartenIdentityRole other)
    {
        return Id.Equals(other.Id)
               && Version.Equals(other.Version)
               && string.Equals(Name, other.Name, StringComparison.Ordinal);
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(null, obj)) return false;
        if (ReferenceEquals(this, obj)) return true;
        return obj.GetType() == GetType()
               && Equals((MartenIdentityRole)obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Id, Version, Name);
    }


    private sealed class NameEqualityComparer : IEqualityComparer<MartenIdentityRole>
    {
        public bool Equals(MartenIdentityRole? x, MartenIdentityRole? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (ReferenceEquals(x, null)) return false;
            if (ReferenceEquals(y, null)) return false;
            return x.GetType() == y.GetType()
                   && string.Equals(x.Name, y.Name, StringComparison.Ordinal);
        }

        public int GetHashCode(MartenIdentityRole obj)
        {
            return StringComparer.Ordinal.GetHashCode(obj.Name);
        }
    }

    /// <summary>
    /// Creates an IEqualityComparer{MartenIdentityRole} which considers the Name property
    /// </summary>
    public static IEqualityComparer<MartenIdentityRole> NameComparer { get; } = new NameEqualityComparer();
}