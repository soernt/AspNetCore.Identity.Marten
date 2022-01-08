using System.Diagnostics;
using Marten.Services;
using Npgsql;
using Xunit.Abstractions;

namespace Marten.AspNetCore.Identity.Tests.Support
{
    public class MartenTestConsoleLogger: IMartenLogger, IMartenSessionLogger
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private Stopwatch? _stopwatch;

        public MartenTestConsoleLogger(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        public IMartenSessionLogger StartSession(IQuerySession session)
        {
            return this;
        }

        public void SchemaChange(string sql)
        {
            /*
            _testOutputHelper.WriteLine("=======================================");
            _testOutputHelper.WriteLine("Executing DDL change:");
            _testOutputHelper.WriteLine("=======================================");
            _testOutputHelper.WriteLine(sql);
            _testOutputHelper.WriteLine("");
            */
        }

        public void LogSuccess(NpgsqlCommand command)
        {
            _stopwatch?.Stop();
            _testOutputHelper.WriteLine("=======================================");
            _testOutputHelper.WriteLine(command.CommandText);
            foreach (var p in command.Parameters.OfType<NpgsqlParameter>())
            {
                _testOutputHelper.WriteLine($"  {p.ParameterName}: {p.Value}");
            }
            _testOutputHelper.WriteLine($"[Duration {_stopwatch?.ElapsedMilliseconds ?? 0} ms]");
        }

        public void LogFailure(NpgsqlCommand command, Exception ex)
        {
            _stopwatch?.Stop();
            _testOutputHelper.WriteLine("=======================================");
            _testOutputHelper.WriteLine("Postgresql command failed!");
            _testOutputHelper.WriteLine("=======================================");
            _testOutputHelper.WriteLine(command.CommandText);
            foreach (var p in command.Parameters.OfType<NpgsqlParameter>())
            {
                _testOutputHelper.WriteLine($"  {p.ParameterName}: {p.Value}");
            }
            _testOutputHelper.WriteLine($"[Duration {_stopwatch?.ElapsedMilliseconds ?? 0} ms]");
            _testOutputHelper.WriteLine(ex.Message);
        }

        public void RecordSavedChanges(IDocumentSession session, IChangeSet commit)
        {
            _stopwatch?.Stop();
            _testOutputHelper.WriteLine("=======================================");
            _testOutputHelper.WriteLine(
                $"Persisted: Inserts {commit.Inserted.Count()} | Updates: {commit.Updated.Count()} | Deletions {commit.Deleted.Count()}");
            _testOutputHelper.WriteLine($"[Duration {_stopwatch?.ElapsedMilliseconds ?? 0} ms]");
        }

        public void OnBeforeExecute(NpgsqlCommand command)
        {
            _stopwatch = new Stopwatch();
            _stopwatch.Start();
        }
    }
}