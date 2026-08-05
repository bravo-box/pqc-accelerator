namespace PQCDashboard.Models;

public record ComplianceRecord(
    DateTimeOffset TimeGenerated,
    string Hostname,
    string Platform,
    string OsVersion,
    string CheckName,
    string Category,
    string Status,
    string Details,
    string GapType,
    string Severity,
    string AffectedComponent,
    string Recommendation,
    double PriorityScore
);

public record MachineSummary(
    string Hostname,
    string Platform,
    string OsVersion,
    DateTimeOffset LastSeen,
    int TotalChecks,
    int CompliantChecks,
    int NonCompliantChecks,
    int GapCount,
    List<GapSummary> Gaps
);

public record GapSummary(
    string GapType,
    string Severity,
    string AffectedComponent,
    string Recommendation,
    double PriorityScore
);

public record FleetSummary(
    int TotalMachines,
    int FullyCompliantMachines,
    int MachinesWithGaps,
    int TotalGaps,
    int CriticalGaps,
    int HighGaps,
    int MediumGaps,
    int LowGaps,
    DateTimeOffset LastRefreshed,
    List<MachineSummary> Machines
);
