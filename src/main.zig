const std = @import("std");
const azure_auth = @import("./azure_auth.zig");
const keyvault = @import("./azure_keyvault.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // Replace these with your values
    const client_id = "";
    const client_secret = "";
    const tenant_id = "";
    const vault_name = "";
    const secret_name = "";
    const new_secret_value = "";
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
    // var secret = try keyvault.get_secret(allocator, token.secure_token, vault_name, secret_name, api_version);
    // defer secret.deinit(allocator);
    // std.debug.print("Secret value: {s}\n", .{secret.value});

    // Try to change the secret value
    const secret = try keyvault.set_secret(allocator, token.secure_token, vault_name, secret_name, new_secret_value, api_version);
    defer secret.deinit(allocator);

    // Fetch it again to see if it changed
    const changed_secret = try keyvault.get_secret(allocator, token.secure_token, vault_name, secret_name, api_version);
    defer changed_secret.deinit(allocator);
    std.debug.print("Secret value: {s}\n", .{changed_secret.value});
}
