using Azure.Identity;
using Azure.Monitor.Query;
using PQCDashboard.Services;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = Directory.GetCurrentDirectory(),
    WebRootPath = Path.Combine(Directory.GetCurrentDirectory(), "ClientApp", "build")
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Register Log Analytics query client for Azure Government
builder.Services.AddSingleton<LogsQueryClient>(_ =>
{
    var options = new LogsQueryClientOptions
    {
        Audience = LogsQueryAudience.AzureGovernment
    };
    return new LogsQueryClient(new DefaultAzureCredential(), options);
});

builder.Services.AddSingleton<ComplianceQueryService>();

builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.WithOrigins("http://localhost:3000").AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();
app.MapControllers();
app.MapFallbackToFile("index.html");

app.Run();
