using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using PQCDashboard.Models;

namespace PQCDashboard.Services;

public class ComplianceQueryService(LogsQueryClient client, IConfiguration config)
{
    private readonly string _workspaceId = config["LogAnalytics:WorkspaceId"]!;
    private readonly string _table       = config["LogAnalytics:TableName"] ?? "PQCCompliance_CL";

    public async Task<FleetSummary> GetFleetSummaryAsync(int lookbackHours = 24)
    {
        var timespan = TimeSpan.FromHours(lookbackHours);

        // Get latest record per machine (most recent scan per hostname)
        var kql = $"""
            {_table}
            | where TimeGenerated > ago({lookbackHours}h)
            | extend
                                record_type = coalesce(tostring(column_ifexists("record_type_s", "")), tostring(column_ifexists("record_type", "")), tostring(column_ifexists("RecordType", ""))),
                                record_hash = coalesce(tostring(column_ifexists("record_hash_s", "")), tostring(column_ifexists("record_hash", "")), tostring(column_ifexists("RecordHash", ""))),
                hostname = coalesce(tostring(column_ifexists("hostname_s", "")), tostring(column_ifexists("hostname", "")), tostring(column_ifexists("MachineName", ""))),
                platform = coalesce(tostring(column_ifexists("platform_s", "")), tostring(column_ifexists("platform", "")), tostring(column_ifexists("Platform", ""))),
                os_version = coalesce(tostring(column_ifexists("os_version_s", "")), tostring(column_ifexists("os_version", "")), tostring(column_ifexists("OSVersion", ""))),
                check_name = coalesce(tostring(column_ifexists("check_name_s", "")), tostring(column_ifexists("check_name", "")), tostring(column_ifexists("CheckName", ""))),
                category = coalesce(tostring(column_ifexists("category_s", "")), tostring(column_ifexists("category", "")), tostring(column_ifexists("Category", ""))),
                status = coalesce(tostring(column_ifexists("status_s", "")), tostring(column_ifexists("status", "")), tostring(column_ifexists("Status", ""))),
                details = coalesce(tostring(column_ifexists("details_s", "")), tostring(column_ifexists("details", "")), tostring(column_ifexists("Details", ""))),
                gap_type = coalesce(tostring(column_ifexists("gap_type_s", "")), tostring(column_ifexists("gap_type", "")), tostring(column_ifexists("GapType", ""))),
                severity = coalesce(tostring(column_ifexists("severity_s", "")), tostring(column_ifexists("severity", "")), tostring(column_ifexists("Severity", ""))),
                affected_component = coalesce(tostring(column_ifexists("affected_component_s", "")), tostring(column_ifexists("affected_component", "")), tostring(column_ifexists("AffectedComponent", ""))),
                recommendation = coalesce(tostring(column_ifexists("recommendation_s", "")), tostring(column_ifexists("recommendation", "")), tostring(column_ifexists("Recommendation", ""))),
                priority_score = todouble(coalesce(column_ifexists("priority_score_d", real(null)), column_ifexists("priority_score", real(null)), column_ifexists("PriorityScore", real(null)), 0.0))
                        | extend dedup_key = iff(
                                isempty(record_hash),
                                strcat(hostname, "|", record_type, "|", check_name, "|", gap_type, "|", severity, "|", status, "|", details),
                                record_hash
                            )
                        | summarize arg_max(TimeGenerated, *) by dedup_key
            | project TimeGenerated, hostname, platform, os_version,
                                            record_type, check_name, category, status, details,
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
            | extend hostname = coalesce(tostring(column_ifexists("hostname_s", "")), tostring(column_ifexists("hostname", "")), tostring(column_ifexists("MachineName", "")))
            | where hostname == '{hostname.Replace("'", "''")}'
            | extend
                                record_type = coalesce(tostring(column_ifexists("record_type_s", "")), tostring(column_ifexists("record_type", "")), tostring(column_ifexists("RecordType", ""))),
                                record_hash = coalesce(tostring(column_ifexists("record_hash_s", "")), tostring(column_ifexists("record_hash", "")), tostring(column_ifexists("RecordHash", ""))),
                platform = coalesce(tostring(column_ifexists("platform_s", "")), tostring(column_ifexists("platform", "")), tostring(column_ifexists("Platform", ""))),
                check_name = coalesce(tostring(column_ifexists("check_name_s", "")), tostring(column_ifexists("check_name", "")), tostring(column_ifexists("CheckName", ""))),
                status = coalesce(tostring(column_ifexists("status_s", "")), tostring(column_ifexists("status", "")), tostring(column_ifexists("Status", ""))),
                details = coalesce(tostring(column_ifexists("details_s", "")), tostring(column_ifexists("details", "")), tostring(column_ifexists("Details", ""))),
                gap_type = coalesce(tostring(column_ifexists("gap_type_s", "")), tostring(column_ifexists("gap_type", "")), tostring(column_ifexists("GapType", ""))),
                severity = coalesce(tostring(column_ifexists("severity_s", "")), tostring(column_ifexists("severity", "")), tostring(column_ifexists("Severity", ""))),
                recommendation = coalesce(tostring(column_ifexists("recommendation_s", "")), tostring(column_ifexists("recommendation", "")), tostring(column_ifexists("Recommendation", "")))
                        | extend dedup_key = iff(
                                isempty(record_hash),
                                strcat(hostname, "|", record_type, "|", check_name, "|", gap_type, "|", severity, "|", status, "|", details),
                                record_hash
                            )
                        | summarize arg_max(TimeGenerated, *) by dedup_key
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
