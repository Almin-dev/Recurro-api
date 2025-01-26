using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.Text;
using recurro.api.Data;
using recurro.api.Models;
using recurro.api.Services;
using DotNetEnv;

// Load environment variables from .env file
Env.Load();

var builder = WebApplication.CreateBuilder(args);

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// Add SQLite database context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ??
    "Data Source=app.db"));

// Add Identity services
builder.Services.AddIdentity<UserModel, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Add authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "YourAppName.Identity";
    options.LoginPath = "/auth/login";
    options.LogoutPath = "/auth/logout";
})
.AddJwtBearer(options =>
{
    var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? "YourSecretKeyHere";
    Console.WriteLine("Using JWT_KEY for TokenValidationParameters: " + jwtKey);

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

// Console.WriteLine("JWT_KEY: " + Environment.GetEnvironmentVariable("JWT_KEY"));

// Add email sender service
builder.Services.AddTransient<IEmailSender, EmailSender>();

// Add rate limiting services
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.Configure<IpRateLimitPolicies>(builder.Configuration.GetSection("IpRateLimitPolicies"));
builder.Services.AddInMemoryRateLimiting();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

// Add CORS configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin",
        builder => builder.WithOrigins("http://example.com")
                          .AllowAnyHeader()
                          .AllowAnyMethod());
});

// Add health checks
builder.Services.AddHealthChecks();

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Recurro API", Version = "v1" });

    // Add security definitions
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});



var app = builder.Build();

// Configure middleware pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
        options.EnableDeepLinking();
        options.DisplayRequestDuration();
    });
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Add CORS middleware
app.UseCors("AllowSpecificOrigin");

// Add rate limiting middleware
app.UseIpRateLimiting();

// Add health checks middleware
app.UseHealthChecks("/health");

app.MapControllers();

// Ensure database is created and seed roles
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<UserModel>>();
    await SeedRolesAsync(roleManager, userManager);
    // await AssignRolesToExistingUsersAsync(userManager);
}

app.Run();

async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager, UserManager<UserModel> userManager)
{
    var roles = new[] { "Admin", "User" };

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }

    // Optionally, create an admin user and assign the Admin role
    // var adminEmail = "admin@example.com";
    // var adminUser = await userManager.FindByEmailAsync(adminEmail);
    // if (adminUser == null)
    // {
    //     adminUser = new UserModel { UserName = "admin", Email = adminEmail };
    //     await userManager.CreateAsync(adminUser, "Admin@123");
    //     await userManager.AddToRoleAsync(adminUser, "Admin");
    // }
}

// async Task AssignRolesToExistingUsersAsync(UserManager<UserModel> userManager)
// {
//     var users = userManager.Users.ToList();
//     foreach (var user in users)
//     {
//         if (user.UserName == "almin")
//         {
//             if (!await userManager.IsInRoleAsync(user, "Admin"))
//             {
//                 await userManager.AddToRoleAsync(user, "Admin");
//             }
//         }
//         else
//         {
//             if (!await userManager.IsInRoleAsync(user, "User"))
//             {
//                 await userManager.AddToRoleAsync(user, "User");
//             }
//         }
//     }
// }