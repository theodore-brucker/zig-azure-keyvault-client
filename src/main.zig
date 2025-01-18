const std = @import("std");
const azure_auth = @import("./azure_auth.zig");
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
    const secret_name = "AmumuKey";
    const api_version = "7.3";

    // Get OAuth token securely
    var token = try azure_auth.getOAuthToken(allocator, client_id, client_secret, tenant_id);
    defer token.deinit();

    // Test authentication
    const auth_success = try keyvault.test_auth(allocator, token.secure_token, vault_name, api_version);
    if (!auth_success) {
        std.debug.print("Authentication test failed\n", .{});
        return;
    }

    // List secrets
    const secret_list = try keyvault.list_secrets(allocator, token.secure_token, vault_name, api_version);
    defer secret_list.deinit(allocator);

    // Print the secret IDs
    for (secret_list.items) |item| {
        std.debug.print("Secret ID: {s}\n", .{item.id});
    }

    // Get a specific secret value
    const secret = try keyvault.get_secret(allocator, token.secure_token, vault_name, secret_name, api_version);
    defer secret.deinit(allocator);

    // Access the secret value
    std.debug.print("Secret value: {s}\n", .{secret.value});
}
