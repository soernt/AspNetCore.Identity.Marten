using Marten.AspNetCore.Identity.Models;
using Marten.AspNetCore.Identity.RoleStore;
using Marten.AspNetCore.Identity.UserStore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Marten.AspNetCore.Identity.Configuration;

/// <summary>
/// IServiceCollection extensions to configure MartenIdentity within Marten
/// </summary>
public static class MartenIdentityServiceCollectionExtensions
{
    /// <summary>
    /// Adds  <see cref="MartenUserStore{MartenIdentityUser, MartenIdentityRole>"/> as <see cref="IUserStore{MartenIdentityUser}"/>
    /// and <see cref="MartenRoleStore{MartenIdentiyRole}"/> as <see cref="IRoleStore{MartneIdentityRole}"/>
    /// </summary>
    /// <param name="services"> <see cref="IServiceCollection"/> </param>
    /// <returns><see cref="IServiceCollection"/> to continue method chaining.</returns>
    public static IServiceCollection AddMartenIdentityStores(this IServiceCollection services)
    {
        return services.AddMartenIdentityStores<MartenIdentityUser, MartenIdentityRole>();
    }

    /// <summary>
    /// Adds  <see cref="MartenUserStore{TUser, TRole}"/> with the given User and Role types as <see cref="IUserStore{MartenIdentityUser}"/>
    /// and <see cref="MartenRoleStore{TRole}"/> with the given Role type as <see cref="IRoleStore{MartneIdentityRole}"/>
    /// </summary>
    /// <param name="services"> <see cref="IServiceCollection"/> </param>
    /// <returns><see cref="IServiceCollection"/> to continue method chaining.</returns>
    public static IServiceCollection AddMartenIdentityStores<TUser, TRole>(this IServiceCollection services)
        where TUser : MartenIdentityUser
        where TRole : MartenIdentityRole
    {
        services.AddScoped<IUserStore<TUser>, MartenUserStore<TUser, TRole>>();
        services.AddScoped<IRoleStore<TRole>, MartenRoleStore<TRole>>();

        return services;
    }
}