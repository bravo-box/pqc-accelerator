using Microsoft.AspNetCore.Mvc;
using PQCDashboard.Services;

namespace PQCDashboard.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ComplianceController(ComplianceQueryService svc) : ControllerBase
{
    [HttpGet("fleet")]
    public async Task<IActionResult> GetFleet([FromQuery] int hours = 24)
    {
        try { return Ok(await svc.GetFleetSummaryAsync(hours)); }
        catch (Exception ex) { return StatusCode(500, new { error = ex.Message }); }
    }

    [HttpGet("machine/{hostname}")]
    public async Task<IActionResult> GetMachine(string hostname, [FromQuery] int hours = 168)
    {
        try { return Ok(await svc.GetMachineHistoryAsync(hostname, hours)); }
        catch (Exception ex) { return StatusCode(500, new { error = ex.Message }); }
    }
}
