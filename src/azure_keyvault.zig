const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
const azure_auth = @import("./azure_auth.zig");

//Define the errors
pub const KeyVaultError = error{
    RequestFailed,
    InvalidResponse,
    SecretNotFound,
    AuthenticationFailed,
    InvalidRequest,
};

pub const SecretAttributes = struct {
    enabled: bool,
    created: i64,
    updated: i64,
    recoveryLevel: []const u8,
    recoverableDays: i64,
};

pub const Secret = struct {
    value: []const u8,
    id: []const u8,
    raw_response: []const u8,

    pub fn deinit(self: *const Secret, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
        allocator.free(self.id);
        allocator.free(self.raw_response);
    }
};

pub const SecretItem = struct {
    id: []const u8,
    enabled: bool,
    created: i64,
    updated: i64,

    pub fn deinit(self: *const SecretItem, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
    }
};

pub const SecretList = struct {
    items: []SecretItem,
    next_link: ?[]const u8,

    pub fn deinit(self: *const SecretList, allocator: std.mem.Allocator) void {
        for (self.items) |*item| {
            item.deinit(allocator);
        }
        allocator.free(self.items);
        if (self.next_link) |link| {
            allocator.free(link);
        }
    }
};

//Function to test the auth token
pub fn test_auth(
    allocator: std.mem.Allocator,
    secure_token: azure_auth.SecureToken,
    vault_name: []const u8,
    api_version: []const u8,
) !bool {
    std.debug.print("[AUTH] Verifying Key Vault access...\n", .{});

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets?maxresults=1&api-version={s}",
        .{ vault_name, api_version },
    );
    defer allocator.free(url);

    // Get a temporary copy of the token for this request
    const token_copy = try secure_token.getToken(allocator);
    defer {
        @memset(token_copy, 0);
        allocator.free(token_copy);
    }

    // Create the proper authorization header value
    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token_copy},
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

    return switch (req.response.status) {
        .ok => {
            std.debug.print("[AUTH] Access verified successfully\n", .{});
            return true;
        },
        .unauthorized, .forbidden => {
            std.debug.print("[AUTH] Access denied\n", .{});
            return false;
        },
        else => {
            std.debug.print("[AUTH] Unexpected error: {s}\n", .{@tagName(req.response.status)});
            return KeyVaultError.RequestFailed;
        },
    };
}

//Function to list all of the secrets in the vault
pub fn list_secrets(
    allocator: std.mem.Allocator,
    secure_token: azure_auth.SecureToken,
    vault_name: []const u8,
    api_version: []const u8,
) !SecretList {
    std.debug.print("[VAULT] Retrieving secrets list...\n", .{});

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets?api-version={s}",
        .{ vault_name, api_version },
    );
    defer allocator.free(url);

    const token_copy = try secure_token.getToken(allocator);
    defer {
        @memset(token_copy, 0);
        allocator.free(token_copy);
    }

    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token_copy},
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
        std.debug.print("[VAULT] Failed to retrieve secrets\n", .{});
        return KeyVaultError.RequestFailed;
    }

    var response_buffer: [8192]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);
    const raw_response = response_buffer[0..read_amount];

    // Parse JSON
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        raw_response,
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value.object;
    const value_array = root.get("value").?.array;

    // Allocate array for SecretItems
    var items = try allocator.alloc(SecretItem, value_array.items.len);

    // Parse each secret item
    for (value_array.items, 0..) |item, i| {
        const obj = item.object;
        const id = try allocator.dupe(u8, obj.get("id").?.string);
        const attributes = obj.get("attributes").?.object;

        items[i] = SecretItem{
            .id = id,
            .enabled = attributes.get("enabled").?.bool,
            .created = attributes.get("created").?.integer,
            .updated = attributes.get("updated").?.integer,
        };
    }

    // Handle nextLink (which may be null)
    var next_link: ?[]const u8 = null;
    if (root.get("nextLink")) |link| {
        if (link != .null) {
            next_link = try allocator.dupe(u8, link.string);
        }
    }

    std.debug.print("[VAULT] Successfully parsed {} secrets\n", .{items.len});

    return SecretList{
        .items = items,
        .next_link = next_link,
    };
}

pub fn get_secret(
    allocator: std.mem.Allocator,
    secure_token: azure_auth.SecureToken,
    vault_name: []const u8,
    secret_name: []const u8,
    api_version: []const u8,
) !Secret {
    std.debug.print("[VAULT] Fetching secret: {s}\n", .{secret_name});

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets/{s}?api-version={s}",
        .{ vault_name, secret_name, api_version },
    );
    defer allocator.free(url);

    const token_copy = try secure_token.getToken(allocator);
    defer {
        @memset(token_copy, 0);
        allocator.free(token_copy);
    }

    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token_copy},
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

    switch (req.response.status) {
        .ok => {},
        .not_found => {
            std.debug.print("[VAULT] Secret not found: {s}\n", .{secret_name});
            return KeyVaultError.SecretNotFound;
        },
        .unauthorized, .forbidden => {
            std.debug.print("[VAULT] Access denied\n", .{});
            return KeyVaultError.AuthenticationFailed;
        },
        else => {
            std.debug.print("[VAULT] Request failed with status: {s}\n", .{@tagName(req.response.status)});
            return KeyVaultError.RequestFailed;
        },
    }

    var response_buffer: [8192]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);

    // Store the raw response
    const raw_response = try allocator.dupe(u8, response_buffer[0..read_amount]);

    // Parse JSON
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        raw_response,
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value.object;

    // Extract required fields
    const value = try allocator.dupe(u8, root.get("value").?.string);
    const id = try allocator.dupe(u8, root.get("id").?.string);

    std.debug.print("[VAULT] Secret retrieved successfully\n", .{});

    return Secret{
        .value = value,
        .id = id,
        .raw_response = raw_response,
    };
}

pub fn set_secret(
    allocator: std.mem.Allocator,
    secure_token: azure_auth.SecureToken,
    vault_name: []const u8,
    secret_name: []const u8,
    secret_value: []const u8,
    api_version: []const u8,
) !Secret {
    std.debug.print("[VAULT] Setting secret: {s}\n", .{secret_name});

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Construct the URL
    const url = try std.fmt.allocPrint(
        allocator,
        "https://{s}.vault.azure.net/secrets/{s}?api-version={s}",
        .{ vault_name, secret_name, api_version },
    );
    defer allocator.free(url);

    // Handle authentication token
    const token_copy = try secure_token.getToken(allocator);
    defer {
        @memset(token_copy, 0);
        allocator.free(token_copy);
    }

    const auth_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{token_copy},
    );
    defer allocator.free(auth_header);

    // Construct request payload
    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();

    const writer = payload.writer();
    try std.json.stringify(.{
        .value = secret_value,
        .attributes = .{
            .enabled = true,
        },
        .tags = .{
            .@"file-encoding" = "utf-8",
        },
    }, .{}, writer);

    // Setup HTTP request
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
    req.transfer_encoding = .{ .content_length = payload.items.len };
    // Let's add some debug printing to see what's happening
    std.debug.print("[VAULT] Sending request with payload size: {d}\n", .{payload.items.len});
    std.debug.print("[VAULT] Payload: {s}\n", .{payload.items});

    // First send the headers
    try req.send();
    // Then write the body
    try req.writer().writeAll(payload.items);
    // Finally finish the request
    try req.finish();
    try req.wait();

    // Handle response status
    switch (req.response.status) {
        .ok, .created => {},
        .unauthorized, .forbidden => {
            std.debug.print("[VAULT] Access denied\n", .{});
            return KeyVaultError.AuthenticationFailed;
        },
        .bad_request => {
            std.debug.print("[VAULT] Bad request\n", .{});
            return KeyVaultError.InvalidRequest;
        },
        else => {
            std.debug.print("[VAULT] Request failed with status: {s}\n", .{@tagName(req.response.status)});
            return KeyVaultError.RequestFailed;
        },
    }

    // Read and parse response
    var response_buffer: [8192]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);

    // Store the raw response
    const raw_response = try allocator.dupe(u8, response_buffer[0..read_amount]);

    // Parse JSON
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        raw_response,
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value.object;

    // Extract required fields
    const value = try allocator.dupe(u8, root.get("value").?.string);
    const id = try allocator.dupe(u8, root.get("id").?.string);

    std.debug.print("[VAULT] Secret set successfully\n", .{});

    return Secret{
        .value = value,
        .id = id,
        .raw_response = raw_response,
    };
}
