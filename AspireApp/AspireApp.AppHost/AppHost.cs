using Projects;

var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<WebApplicationAPI>("WebApplicationAPI");
builder.AddProject<WebApplicationJWT>("WebApplicationJWT");

builder.Build().Run();