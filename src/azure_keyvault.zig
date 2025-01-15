const std = @import("std");
const json = std.json;

//Define the errors
pub const KeyVaultError = error{
    RequestFailed,
    InvalidResponse,
    SecretNotFound,
    AuthenticationFailed,
};

//Struct for secrets
pub const Secret = struct {
    id: []const u8,
    value: []const u8,
    name: []const u8,

    pub fn deinit(self: *const Secret, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.value);
        allocator.free(self.name);
    }
};

//Struct for a list of secrets
pub const SecretList = struct {
    value: []Secret,

    pub fn deinit(self: *const SecretList, allocator: std.mem.Allocator) void {
        for (self.value) |secret| {
            secret.deinit(allocator);
        }
        allocator.free(self.value);
    }
};

//Function to test the auth token
pub fn test_auth(
    allocator: std.mem.Allocator,
    token: []const u8,
    vault_name: []const u8,
    api_version: []const u8,
) !bool {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets?maxresults=1&api-version={s}",
        .{ vault_name, api_version },
    );
    defer allocator.free(url);

    // Create the proper authorization header value
    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token},
    );
    defer allocator.free(auth_header);

    const uri = try std.Uri.parse(url);

    var server_header_buffer: [4092]u8 = undefined;
    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .headers = .{
            .authorization = .{ .override = auth_header },
        },
    });
    defer req.deinit();

    try req.send();
    try req.finish();
    try req.wait();

    // Read response body for error details
    var response_buffer: [4096]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);
    const response_body = response_buffer[0..read_amount];

    // Debug information
    std.debug.print("\nDebug Information:\n", .{});
    std.debug.print("URL: {s}\n", .{url});
    std.debug.print("Status: {d} {s}\n", .{ @intFromEnum(req.response.status), @tagName(req.response.status) });

    // Print response body
    std.debug.print("\nResponse Body:\n{s}\n", .{response_body});

    return switch (req.response.status) {
        .ok => true,
        .unauthorized, .forbidden => {
            std.debug.print("\nAuthentication failed!\n", .{});
            return false;
        },
        else => {
            std.debug.print("\nUnexpected response status!\n", .{});
            return KeyVaultError.RequestFailed;
        },
    };
}

//Function to list all of the secrets in the vault
pub fn list_secrets(
    allocator: std.mem.Allocator,
    token: []const u8,
    vault_name: []const u8,
    api_version: []const u8,
) !SecretList {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets?api-version={s}",
        .{ vault_name, api_version },
    );
    defer allocator.free(url);

    // Create the proper authorization header value
    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token},
    );
    defer allocator.free(auth_header);

    const uri = try std.Uri.parse(url);

    var server_header_buffer: [4092]u8 = undefined;
    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .headers = .{
            .authorization = .{ .override = auth_header },
        },
    });
    defer req.deinit();

    try req.send();
    try req.finish();
    try req.wait();

    if (req.response.status != .ok) {
        return KeyVaultError.RequestFailed;
    }

    var response_buffer: [8192]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);
    std.debug.print("Key stuff: {s}\n", .{response_buffer[0..read_amount]});

    const parsed = try json.parseFromSlice(
        SecretList,
        allocator,
        response_buffer[0..read_amount],
        .{},
    );
    defer parsed.deinit();
    std.debug.print("\nFull thing {any}:\n", .{parsed.value});

    return parsed.value;
}

//Function to get a secret
pub fn get_secret(
    allocator: std.mem.Allocator,
    token: []const u8,
    vault_name: []const u8,
    secret_name: []const u8,
    api_version: []const u8,
) !Secret {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets/{s}?api-version={s}",
        .{ vault_name, secret_name, api_version },
    );
    defer allocator.free(url);

    // Create the proper authorization header value
    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token},
    );
    defer allocator.free(auth_header);

    const uri = try std.Uri.parse(url);

    var server_header_buffer: [4092]u8 = undefined;
    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .headers = .{
            .authorization = .{ .override = auth_header },
        },
    });
    defer req.deinit();

    try req.send();
    try req.finish();
    try req.wait();

    if (req.response.status == .not_found) {
        return KeyVaultError.SecretNotFound;
    } else if (req.response.status != .ok) {
        return KeyVaultError.RequestFailed;
    }

    var response_buffer: [4096]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);

    const parsed = try json.parseFromSlice(
        Secret,
        allocator,
        response_buffer[0..read_amount],
        .{},
    );
    defer parsed.deinit();

    return parsed.value;
}

//Function to set a secret
pub fn set_secret(
    allocator: std.mem.Allocator,
    token: []const u8,
    vault_name: []const u8,
    secret_name: []const u8,
    secret_value: []const u8,
    api_version: []const u8,
) !Secret {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets/{s}?api-version={s}",
        .{ vault_name, secret_name, api_version },
    );
    defer allocator.free(url);

    // Create the proper authorization header value
    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token},
    );
    defer allocator.free(auth_header);

    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"value\":\"{s}\"}}",
        .{secret_value},
    );
    defer allocator.free(body);

    const uri = try std.Uri.parse(url);

    var server_header_buffer: [4092]u8 = undefined;
    var req = try client.open(.PUT, uri, .{
        .server_header_buffer = &server_header_buffer,
        .headers = .{
            .authorization = .{ .override = auth_header },
            .content_type = .{ .override = "application/json" },
        },
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = body.len };

    try req.send();
    try req.writer().writeAll(body);
    try req.finish();
    try req.wait();

    if (req.response.status != .ok) {
        return KeyVaultError.RequestFailed;
    }

    var response_buffer: [4096]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);

    const parsed = try json.parseFromSlice(
        Secret,
        allocator,
        response_buffer[0..read_amount],
        .{},
    );
    defer parsed.deinit();

    return parsed.value;
}
