using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using PQCDashboard.Models;

namespace PQCDashboard.Services;

public class ComplianceQueryService(LogsQueryClient client, IConfiguration config)
{
    private readonly string _workspaceId = config["LogAnalytics:WorkspaceId"]!;
    private readonly string _table       = config["LogAnalytics:TableName"] ?? "PQCValidation_CL";

    public async Task<FleetSummary> GetFleetSummaryAsync(int lookbackHours = 24)
    {
        var timespan = TimeSpan.FromHours(lookbackHours);

        // Get latest record per machine (most recent scan per hostname)
        var kql = $"""
            {_table}
            | where TimeGenerated > ago({lookbackHours}h)
            | summarize arg_max(TimeGenerated, *) by hostname, check_name
            | project TimeGenerated, hostname, platform, os_version,
                      check_name, category, status, details,
                      gap_type, severity, affected_component, recommendation, priority_score
            | sort by hostname asc, priority_score desc
            """;

        var response = await client.QueryWorkspaceAsync(_workspaceId, kql, new QueryTimeRange(timespan));
        var rows = response.Value.Table.Rows;

        var records = rows.Select(r => new ComplianceRecord(
            r.GetDateTimeOffset("TimeGenerated") ?? DateTimeOffset.UtcNow,
            r.GetString("hostname") ?? "",
            r.GetString("platform") ?? "",
            r.GetString("os_version") ?? "",
            r.GetString("check_name") ?? "",
            r.GetString("category") ?? "",
            r.GetString("status") ?? "",
            r.GetString("details") ?? "",
            r.GetString("gap_type") ?? "",
            r.GetString("severity") ?? "",
            r.GetString("affected_component") ?? "",
            r.GetString("recommendation") ?? "",
            r.GetDouble("priority_score") ?? 0
        )).ToList();

        var machines = records
            .GroupBy(r => r.Hostname)
            .Select(g =>
            {
                var checks    = g.Where(r => !string.IsNullOrEmpty(r.CheckName)).ToList();
                var gaps      = g.Where(r => !string.IsNullOrEmpty(r.GapType)).ToList();
                var compliant = checks.Count(r => r.Status == "COMPLIANT");

                return new MachineSummary(
                    Hostname:          g.Key,
                    Platform:          g.First().Platform,
                    OsVersion:         g.First().OsVersion,
                    LastSeen:          g.Max(r => r.TimeGenerated),
                    TotalChecks:       checks.Count,
                    CompliantChecks:   compliant,
                    NonCompliantChecks: checks.Count - compliant,
                    GapCount:          gaps.Count,
                    Gaps: gaps.Select(r => new GapSummary(
                        r.GapType, r.Severity, r.AffectedComponent,
                        r.Recommendation, r.PriorityScore)).ToList()
                );
            })
            .OrderBy(m => m.Hostname)
            .ToList();

        var allGaps = machines.SelectMany(m => m.Gaps).ToList();

        return new FleetSummary(
            TotalMachines:           machines.Count,
            FullyCompliantMachines:  machines.Count(m => m.GapCount == 0),
            MachinesWithGaps:        machines.Count(m => m.GapCount > 0),
            TotalGaps:               allGaps.Count,
            CriticalGaps:            allGaps.Count(g => g.Severity == "CRITICAL"),
            HighGaps:                allGaps.Count(g => g.Severity == "HIGH"),
            MediumGaps:              allGaps.Count(g => g.Severity == "MEDIUM"),
            LowGaps:                 allGaps.Count(g => g.Severity == "LOW"),
            LastRefreshed:           DateTimeOffset.UtcNow,
            Machines:                machines
        );
    }

    public async Task<List<ComplianceRecord>> GetMachineHistoryAsync(string hostname, int lookbackHours = 168)
    {
        var kql = $"""
            {_table}
            | where TimeGenerated > ago({lookbackHours}h)
            | where hostname == '{hostname.Replace("'", "''")}'
            | project TimeGenerated, hostname, platform, check_name, status,
                      gap_type, severity, details, recommendation
            | sort by TimeGenerated desc
            """;

        var response = await client.QueryWorkspaceAsync(
            _workspaceId, kql, new QueryTimeRange(TimeSpan.FromHours(lookbackHours)));

        return response.Value.Table.Rows.Select(r => new ComplianceRecord(
            r.GetDateTimeOffset("TimeGenerated") ?? DateTimeOffset.UtcNow,
            r.GetString("hostname") ?? "",
            r.GetString("platform") ?? "",
            "", r.GetString("check_name") ?? "",
            "", r.GetString("status") ?? "",
            r.GetString("details") ?? "",
            r.GetString("gap_type") ?? "",
            r.GetString("severity") ?? "",
            "", r.GetString("recommendation") ?? "", 0
        )).ToList();
    }
}
