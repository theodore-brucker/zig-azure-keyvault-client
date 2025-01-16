const std = @import("std");
const azure = @import("./azure_auth.zig");
const keyvault = @import("./azure_keyvault.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // Replace these with your values
    const client_id = "760600a2-aa56-4ba2-b1be-1f54ced2feec";
    const client_secret = "1M58Q~y~Z5t1RUx9PVniI2XsrQ7Vz2HDdKcVWcfi";
    const tenant_id = "ce1a7451-84f5-4eaa-bda7-ea1f54772c73";
    const vault_name = "sandbox-zig-vault";
    const api_version = "7.3";

    // Get OAuth token
    const token = try azure.getOAuthToken(allocator, client_id, client_secret, tenant_id);
    defer token.deinit(allocator);

    // Test authentication
    std.debug.print("Testing authentication...\n", .{});
    const is_authenticated = try keyvault.test_auth(allocator, token.access_token, vault_name, api_version);
    if (!is_authenticated) {
        std.debug.print("Authentication failed! Please check your credentials and permissions.\n", .{});
        return keyvault.KeyVaultError.AuthenticationFailed;
    }
    std.debug.print("Authentication successful!\n", .{});

    // List all secrets
    std.debug.print("\nListing all secrets:\n", .{});
    try keyvault.list_secrets(allocator, token.access_token, vault_name, api_version);
    //defer secrets.deinit(allocator);

    // for (secrets.value) |secret| {
    //     std.debug.print("Secret name: {s}\n", .{secret.id});
    // }

    // Set a new secret
    // const new_secret = try keyvault.set_secret(
    //     allocator,
    //     token.access_token,
    //     vault_name,
    //     "test-secret",
    //     "test-value",
    //     api_version,
    // );
    // defer new_secret.deinit(allocator);

    // std.debug.print("\nCreated new secret:\n", .{});
    // std.debug.print("Name: {s}\nValue: {s}\n", .{ new_secret.id, new_secret.attributes });

    // // Get a specific secret
    // const retrieved_secret = try keyvault.get_secret(
    //     allocator,
    //     token.access_token,
    //     vault_name,
    //     "test-secret",
    //     api_version,
    // );
    // defer retrieved_secret.deinit(allocator);

    // std.debug.print("\nRetrieved secret:\n", .{});
    // std.debug.print("Name: {s}\nValue: {s}\n", .{ retrieved_secret.id, retrieved_secret.attributes });
}
