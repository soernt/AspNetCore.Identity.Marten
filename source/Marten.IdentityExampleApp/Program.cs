using Marten;
using Marten.AspNetCore.Identity.Configuration;
using Marten.AspNetCore.Identity.Models;
using Marten.IdentityExampleApp.Infrastructure;
using Microsoft.AspNetCore.Identity.UI.Services;
using Weasel.Core;
using StoreOptions = Marten.StoreOptions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddMarten(options =>
{
    options.Connection(builder.Configuration.GetConnectionString("Marten"));
    // Configure the MartenIdentityUser and MartenIdentityRole mappings
    options.ConfigureMartenIdentityMapping();
    if (builder.Environment.IsDevelopment())
    {
        options.AutoCreateSchemaObjects = AutoCreate.All;
    }
});

// Configure Logging (I didn't find a better way than this) 
builder.Services.AddSingleton<IDocumentStore>(services =>
{
    var logger = services.GetRequiredService<ILogger<IDocumentStore>>();
    var storeOptions = services.GetRequiredService<StoreOptions>();
    storeOptions.Logger(new MartenLogger(logger));
    return new DocumentStore(storeOptions);
});

// Add MartenIdentityUserStore (as IUserStore) and MartenIdentityRoleStore (as IRoleStore)
builder.Services.AddMartenIdentityStores();

// Prints the Mail content to console
builder.Services.AddScoped<IEmailSender, ConsoleEmailSender>();

// Configure Asp.net Core Identity Services.
// builder.Services.AddIdentity<MartenIdentityUser, MartenIdentityRole>();
builder.Services.AddDefaultIdentity<MartenIdentityUser>();

builder.Services.AddHttpsRedirection(opts => {
    opts.HttpsPort = 44350;
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpLogging();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();