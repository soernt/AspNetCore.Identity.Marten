using System.Linq.Expressions;
using Marten.AspNetCore.Identity.Configuration;
using Marten.AspNetCore.Identity.Models;
using Marten.AspNetCore.Identity.RoleStore;
using Marten.AspNetCore.Identity.Tests.Support;
using Marten.AspNetCore.Identity.UserStore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Test;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Xunit.Abstractions;

namespace Marten.AspNetCore.Identity.Tests
{
    /// <summary>
    /// Uses the Microsoft Identity test specifications to test the <see cref="MartenUserStore{User, Role}"/>
    /// and <see cref="MartenRoleStore{Role}"/>
    /// </summary>
    [Collection(UsingDatabaseServerCollection.Name)]
    public class MicrosoftIdentitySpecificationConformanceTests :
        IdentitySpecificationTestBase<MartenIdentityUser, MartenIdentityRole>,
        IClassFixture<MartenDocumentStoreBootstrapFixture>,
        IDisposable
    {
        private readonly IDocumentStore _documentStore;

        public MicrosoftIdentitySpecificationConformanceTests(
            MartenDocumentStoreBootstrapFixture martenDocumentStoreBootstrapFixture,
            ITestOutputHelper testOutputHelper
        )
        {
            _documentStore = martenDocumentStoreBootstrapFixture.ConfigureMartenDocumentStore(options =>
            {
                options.ConfigureMartenIdentityMapping();
                options.Logger(new MartenTestConsoleLogger(testOutputHelper));
            });
        }

        public void Dispose()
        {
            _documentStore.Dispose();
        }

        protected override object? CreateTestContext()
        {
            return null;
        }

        protected override void AddUserStore(IServiceCollection services, object? context = null)
        {
            var userStore = new MartenUserStore<MartenIdentityUser, MartenIdentityRole>(_documentStore);
            services.AddSingleton<IUserStore<MartenIdentityUser>>(userStore);
        }

        protected override void AddRoleStore(IServiceCollection services, object? context = null)
        {
            var roleStore = new MartenRoleStore<MartenIdentityRole>(_documentStore);

            services.AddSingleton<IRoleStore<MartenIdentityRole>>(roleStore);
        }

        protected override void SetUserPasswordHash(MartenIdentityUser user, string hashedPassword)
        {
            user.PasswordHash = hashedPassword;
        }

        protected override MartenIdentityUser CreateTestUser(
            string namePrefix = "",
            string email = "",
            string phoneNumber = "",
            bool lockoutEnabled = false,
            DateTimeOffset? lockoutEnd = null,
            bool useNamePrefixAsUserName = false
        )
        {
            return new MartenIdentityUser
            {
                UserName = useNamePrefixAsUserName ? namePrefix : $"{namePrefix}{Guid.NewGuid()}",
                EmailAddress = email,
                PhoneNumber = phoneNumber,
                IsLockoutEnabled = lockoutEnabled,
                LockoutEndAtUtc = lockoutEnd
            };
        }

        protected override Expression<Func<MartenIdentityUser, bool>> UserNameEqualsPredicate(string userName)
        {
            return user => user.UserName == userName;
        }

        protected override Expression<Func<MartenIdentityUser, bool>> UserNameStartsWithPredicate(string userName)
        {
            return user => user.UserName.StartsWith(userName);
        }

        protected override MartenIdentityRole CreateTestRole(string roleNamePrefix = "",
            bool useRoleNamePrefixAsRoleName = false)
        {
            var roleName = useRoleNamePrefixAsRoleName ? roleNamePrefix : $"{roleNamePrefix}{Guid.NewGuid()}";
            return new MartenIdentityRole(roleName);
        }

        protected override Expression<Func<MartenIdentityRole, bool>> RoleNameEqualsPredicate(string roleName)
        {
            return role => role.Name == roleName;
        }

        protected override Expression<Func<MartenIdentityRole, bool>> RoleNameStartsWithPredicate(string roleName)
        {
            return role => role.Name.StartsWith(roleName);
        }
    }
}