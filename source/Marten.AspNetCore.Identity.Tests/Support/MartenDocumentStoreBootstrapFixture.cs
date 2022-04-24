using System.Data;
using Npgsql;
using Weasel.Core;
using Xunit;

namespace Marten.AspNetCore.Identity.Tests.Support
{
    public class MartenDocumentStoreBootstrapFixture : IAsyncLifetime
    {
        private IDocumentStore? _documentStore;

        private readonly string _schemaName;

        public MartenDocumentStoreBootstrapFixture()
        {
            _schemaName = CreateIntegrationTestSchemaName();
        }

        public IDocumentStore ConfigureMartenDocumentStore(Action<StoreOptions> additionalConfiguration)
        {
            _documentStore = global::Marten.DocumentStore.For(_ =>
            {
                _.Connection(DatabaseServerBootstrapFixture.ConnectionString);
                _.AutoCreateSchemaObjects = AutoCreate.All;
                _.DatabaseSchemaName = _schemaName;
                _.Events.DatabaseSchemaName = _schemaName;
                additionalConfiguration(_);
            });

            return _documentStore;
        }

        private static string CreateIntegrationTestSchemaName()
        {
            return "IntegrationTest_" + Guid.NewGuid()
                .ToString()
                .Replace("-", string.Empty, StringComparison.Ordinal);
        }

        private async Task DeleteDatabaseSchemaAsync()
        {
            var sql = $"DROP SCHEMA IF EXISTS {_schemaName} CASCADE;";
            await using var connection = new NpgsqlConnection(DatabaseServerBootstrapFixture.ConnectionString);
            await connection.OpenAsync().ConfigureAwait(false);
            try
            {
                await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted)
                    .ConfigureAwait(false);
                var command = connection.CreateCommand();
                command.CommandText = sql;
                await command.ExecuteNonQueryAsync().ConfigureAwait(false);
                await transaction.CommitAsync().ConfigureAwait(false);
            }
            finally
            {
                await connection.CloseAsync().ConfigureAwait(false);
            }
        }

        public Task InitializeAsync()
        {
            return Task.CompletedTask;
        }

        public async Task DisposeAsync()
        {
            await DeleteDatabaseSchemaAsync().ConfigureAwait(false);
            _documentStore?.Dispose();
        }
    }
}