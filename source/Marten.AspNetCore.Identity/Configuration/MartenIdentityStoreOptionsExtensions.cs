using Marten.AspNetCore.Identity.Models;
using Marten.Schema.Identity;

namespace Marten.AspNetCore.Identity.Configuration;

/// <summary>
/// StoreOptions extensions to configure MartenIdentity within Marten
/// </summary>
public static class MartenIdentityStoreOptionsExtensions
{
    /// <summary>
    /// Adds MartenIdentity mapping configurations to Marten
    /// </summary>
    /// <param name="storeOptions"></param>
    /// <returns></returns>
    public static StoreOptions ConfigureMartenIdentityMapping(this StoreOptions storeOptions)
    {
        storeOptions.Schema.For<MartenIdentityUser>().ConfigureMartenIdentityUserMapping();
        storeOptions.Schema.For<MartenIdentityRole>().ConfigureMartenIdentityRoleMapping();

        return storeOptions;
    }

    private static void ConfigureMartenIdentityUserMapping(
        this MartenRegistry.DocumentMappingExpression<MartenIdentityUser> mapping)
    {
        mapping
            .IdStrategy(new CombGuidIdGeneration())
            .Index(x => x.NormalizedUserName, x => { x.IsUnique = true; })
            .Index(x => x.NormalizedEmailAddress, x => { x.IsUnique = false; });
    }

    private static void ConfigureMartenIdentityRoleMapping(
        this MartenRegistry.DocumentMappingExpression<MartenIdentityRole> mapping)
    {
        mapping
            .IdStrategy(new CombGuidIdGeneration())
            .Index(x => x.NormalizedName, x => { x.IsUnique = true; });
    }
}