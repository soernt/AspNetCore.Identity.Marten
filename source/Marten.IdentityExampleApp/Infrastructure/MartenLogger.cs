using System.Diagnostics;
using System.Text;
using Baseline;
using Marten.Services;
using Npgsql;

namespace Marten.IdentityExampleApp.Infrastructure;

internal class MartenLogger : IMartenLogger, IMartenSessionLogger
{
    public static LogLevel SchemaChangeLogLevel = LogLevel.Information;

    public static LogLevel LogSuccessLogLevel = LogLevel.Information;

    public static LogLevel LogFailureLogLevel = LogLevel.Information;

    public static LogLevel RecordSavedChangesLogLevel = LogLevel.Information;

    public static LogLevel IncludeExecutionDurationLogLevel = LogLevel.Information;

    private readonly ILogger _logger;
    private Stopwatch? _stopwatch;

    public MartenLogger(ILogger logger)
    {
        _logger = logger;
    }

    public IMartenSessionLogger StartSession(IQuerySession session)
    {
        return this;
    }

    public void SchemaChange(string sql)
    {
        if (!_logger.IsEnabled(SchemaChangeLogLevel))
        {
            return;
        }

        _logger.Log(SchemaChangeLogLevel, "Executed schema update SQL:\n{Sql}", sql);
    }

    public void LogSuccess(NpgsqlCommand command)
    {
        _stopwatch?.Stop();

        if (!_logger.IsEnabled(LogSuccessLogLevel))
        {
            return;
        }

        var parameterInfo = new StringBuilder();
        foreach (NpgsqlParameter p in command.Parameters)
        {
            parameterInfo.AppendLine($"{p.ParameterName}: {p.Value}");
        }

        _logger.Log(LogSuccessLogLevel, "Marten executed in {Milliseconds} ms, SQL: {Sql} Parameters: {Parameters}",
            _stopwatch?.ElapsedMilliseconds ?? 0, 
            command.CommandText, 
            parameterInfo.ToString());
    }

    public void LogFailure(NpgsqlCommand command, Exception ex)
    {
        _stopwatch?.Stop();

        if (!_logger.IsEnabled(LogFailureLogLevel))
        {
            return;
        }

        const string message = "Marten encountered an exception executing \n{SQL}\n{PARAMS}";

        var parameters = command.Parameters.OfType<NpgsqlParameter>()
            .Select(p => $"  {p.ParameterName}: {p.Value}")
            .Join(Environment.NewLine);
        _logger.Log(LogFailureLogLevel, ex, message, command.CommandText, parameters);
    }

    public void RecordSavedChanges(IDocumentSession session, IChangeSet commit)
    {
        _stopwatch?.Stop();

        if (!_logger.IsEnabled(RecordSavedChangesLogLevel))
        {
            return;
        }

        _logger.Log(RecordSavedChangesLogLevel,
            "Persisted {UpdateCount} updates in {ElapsedMilliseconds} ms, {InsertedCount} inserts, and {DeletedCount} deletions",
            commit.Updated.Count(), _stopwatch?.ElapsedMilliseconds ?? 0, commit.Inserted.Count(),
            commit.Deleted.Count());
    }

    public void OnBeforeExecute(NpgsqlCommand command)
    {
        if (!_logger.IsEnabled(IncludeExecutionDurationLogLevel))
        {
            return;
        }

        _stopwatch = new Stopwatch();
        _stopwatch.Start();
    }
}