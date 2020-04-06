// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Api;
using IdentityServer.Data;
using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Serilog;

namespace IdentityServer
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }
     
        public void ConfigureServices(IServiceCollection services)
        {
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
          
            //services.AddSingleton()
            services.AddControllersWithViews();
            services.AddRazorPages().AddSessionStateTempDataProvider();             
            services.AddSession();
            services.AddAuthorization();

            IMSGConfigHelper msgConfigHelper = new MSGConfigHelper(Configuration);

            services.AddSingleton(msgConfigHelper);


            var connectionString = msgConfigHelper.MSGGenDB01;

            services.AddDbContext<ApplicationDbContext>(builder =>
             builder.UseSqlServer(connectionString, sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly)));

            var builder = services.AddIdentityServer(
                o=>o.Cors.CorsPaths.Add(new Microsoft.AspNetCore.Http.PathString("/token"))
                )
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = b =>
                        b.UseSqlServer(connectionString,
                            sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = b =>
                        b.UseSqlServer(connectionString,
                            sql => sql.MigrationsAssembly(migrationsAssembly));

                    // this enables automatic token cleanup. this is optional.
                    options.EnableTokenCleanup = true;
                });
          
            //if (Environment.IsDevelopment())
            //{
            //    builder.AddDeveloperSigningCredential();
            //}
            //else
            //{
                //var key = Configuration["MSGCert01"];

                //var pfxBytes = Convert.FromBase64String(key);
                //var cert = new X509Certificate2(pfxBytes, (string)null, X509KeyStorageFlags.MachineKeySet);
              
                builder.AddSigningCredential(msgConfigHelper.MSGCert01);
            //}

            services.AddAuthentication()
                .AddGoogle("Google", options =>
                {
                    //options.Scope
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.ClaimActions.MapJsonKey("urn:google:picture", "picture", "url");
                    options.ClaimActions.MapJsonKey("urn:google:locale", "locale", "string");
                    options.ClaimActions.MapJsonKey("urn:google:email", "email", "string");

                    options.ClientId = msgConfigHelper.GoogleClientId;// Configuration["GoogleClientId"];
                    options.ClientSecret = msgConfigHelper.GoogleClientSecret;// Configuration["GoogleClientSecret"];

                    options.Events.OnCreatingTicket = ctx =>
                    {
                        List<AuthenticationToken> tokens = ctx.Properties.GetTokens().ToList();

                        tokens.Add(new AuthenticationToken()
                        {
                            Name = "TicketCreated",
                            Value = DateTime.UtcNow.ToString()
                        });

                        ctx.Properties.StoreTokens(tokens);

                        return Task.CompletedTask;
                    };

                    options.AuthorizationEndpoint += "?prompt=consent"; // Hack so we always get a refresh token, it only comes on the first authorization response
                    options.AccessType = "offline";
                    options.SaveTokens = true;
                })

                .AddJwtBearer("Bearer", options =>
                {
                    options.Authority = msgConfigHelper.AuthServerUrl;
                    options.RequireHttpsMetadata = false;
                    options.Audience = "api1";
                });

            services.AddCors(options =>
            {
                options.AddPolicy("api", policy =>
                {
                    policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
                });
            });

        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseCookiePolicy();
            app.UseSerilogRequestLogging();
            app.UseCors("api");
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();
             
            app.UseStaticFiles();

            app.UseIdentityServer();
           
            app.UseSession(); // This must come before "UseMvc()"
                              //  app.UseHttpContextItemsMiddleware();

            
            
            app.UseEndpoints(endpoints =>
            {

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
            //  app.UseMvcWithDefaultRoute();
        }
    }
}