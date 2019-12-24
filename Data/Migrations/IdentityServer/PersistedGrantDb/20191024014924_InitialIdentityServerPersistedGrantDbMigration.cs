using Microsoft.EntityFrameworkCore.Migrations;

namespace IdentityServer.Data.Migrations.IdentityServer.PersistedGrantDb
{
    public partial class InitialIdentityServerPersistedGrantDbMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_PersistedGrants_Expiration",
                table: "PersistedGrants",
                column: "Expiration");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceCodes_Expiration",
                table: "DeviceCodes",
                column: "Expiration");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PersistedGrants_Expiration",
                table: "PersistedGrants");

            migrationBuilder.DropIndex(
                name: "IX_DeviceCodes_Expiration",
                table: "DeviceCodes");
        }
    }
}
