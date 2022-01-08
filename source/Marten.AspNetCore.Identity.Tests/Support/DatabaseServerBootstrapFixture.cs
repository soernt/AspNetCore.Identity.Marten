using DotNet.Testcontainers.Containers.Builders;
using DotNet.Testcontainers.Containers.Configurations.Databases;
using DotNet.Testcontainers.Containers.Modules.Databases;
using Xunit;

namespace Marten.AspNetCore.Identity.Tests.Support
{
    public class DatabaseServerBootstrapFixture : IAsyncLifetime
    {
        private readonly PostgreSqlTestcontainer _postgreSqlContainer;

        private const string DatabaseName = "aspnetidentity";
        private const string DatabaseUserName = "aspnetidentity";
        private const string DatabaseUserPassword = "aspnetidentity";
        private const int DatabaseHostPort = 5435;

        public static readonly string ConnectionString;

        static DatabaseServerBootstrapFixture()
        {
            ConnectionString = "HOST = 127.0.0.1; " +
                               $"PORT = {DatabaseHostPort}; " +
                               $"DATABASE = '{DatabaseName}'; " +
                               $"USER ID = '{DatabaseUserName}'; " +
                               $"PASSWORD = '{DatabaseUserPassword}'; " +
                               "TIMEOUT = 15; " +
                               "POOLING = True; " +
                               "MINPOOLSIZE = 1; " +
                               "MAXPOOLSIZE = 100; " +
                               "COMMANDTIMEOUT = 20; ";
        }

        public DatabaseServerBootstrapFixture()
        {
            var testContainerBuilder = new TestcontainersBuilder<PostgreSqlTestcontainer>()
                    .WithCleanUp(true)
                    .WithDatabase(new PostgreSqlTestcontainerConfiguration
                    {
                        Database = DatabaseName,
                        Username = DatabaseUserName,
                        Password = DatabaseUserPassword
                    })
                    .WithPortBinding(DatabaseHostPort, 5432)
                    .WithImage("clkao/postgres-plv8")
                    .WithName("MartenAspNetIdentityTestDb")
                ;

            _postgreSqlContainer = testContainerBuilder.Build();
        }

        public async Task InitializeAsync()
        {
            await _postgreSqlContainer.StartAsync().ConfigureAwait(false);

            var result = await _postgreSqlContainer.ExecAsync(new[]
                {
                    "/bin/sh", "-c",
                    $"psql -U {DatabaseUserName} -c \"CREATE EXTENSION plv8; SELECT extversion FROM pg_extensions WHERE extname = 'plv8';\""
                })
                .ConfigureAwait(false);
        }

        public async Task DisposeAsync()
        {
            await _postgreSqlContainer.CleanUpAsync().ConfigureAwait(false);
        }
    }
}