using Xunit;

namespace Marten.AspNetCore.Identity.Tests.Support
{
    [CollectionDefinition(UsingDatabaseServerCollection.Name)]
    public class UsingDatabaseServerCollection : ICollectionFixture<DatabaseServerBootstrapFixture>
    {
        public const string Name = "UsingDatabaseServerCollection";
    }
}