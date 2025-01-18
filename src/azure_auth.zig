const std = @import("std");
const json = std.json;
const mem = std.mem;
const crypto = std.crypto;

pub const OAuthError = error{
    RequestFailed,
    InvalidResponse,
};

pub const OAuthResponse = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: u32,
    ext_expires_in: u32,
};

pub const SecureToken = struct {
    buffer: []u8,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, token: []const u8) !SecureToken {
        // Create a secure buffer for the token
        const buffer = try allocator.alloc(u8, token.len);
        @memcpy(buffer, token);

        return SecureToken{
            .buffer = buffer,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SecureToken) void {
        // Zero out memory before freeing
        @memset(self.buffer, 0);
        self.allocator.free(self.buffer);
    }

    pub fn verify(self: SecureToken, other: []const u8) bool {
        if (self.buffer.len != other.len) return false;
        return crypto.utils.timingSafeEql(u8, self.buffer, other);
    }

    pub fn getToken(self: SecureToken, allocator: mem.Allocator) ![]u8 {
        const token_copy = try allocator.dupe(u8, self.buffer);
        return token_copy;
    }
};

// Modified OAuthToken to use SecureToken
pub const OAuthToken = struct {
    secure_token: SecureToken,
    token_type: []const u8,
    expires_in: u32,
    ext_expires_in: u32,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, access_token: []const u8, token_type: []const u8, expires_in: u32, ext_expires_in: u32) !OAuthToken {
        std.debug.print("\n[TOKEN] Initializing secure OAuth token\n", .{});
        const token = OAuthToken{
            .secure_token = try SecureToken.init(allocator, access_token),
            .token_type = try allocator.dupe(u8, token_type),
            .expires_in = expires_in,
            .ext_expires_in = ext_expires_in,
            .allocator = allocator,
        };
        return token;
    }

    pub fn deinit(self: *OAuthToken) void {
        std.debug.print("[TOKEN] Secure cleanup complete\n", .{});
        self.secure_token.deinit();
        self.allocator.free(self.token_type);
    }
};

pub fn getOAuthToken(allocator: std.mem.Allocator, client_id: []const u8, client_secret: []const u8, tenant_id: []const u8) !OAuthToken {
    // Create an HTTP client
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Microsoft OAuth2 configuration
    const token_url = try std.fmt.allocPrint(
        allocator,
        "https://login.microsoftonline.com/{s}/oauth2/v2.0/token",
        .{tenant_id},
    );
    defer allocator.free(token_url);

    const scope = "https%3A%2F%2Fvault.azure.net%2F.default";

    // Prepare the request body with proper formatting
    const body = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&scope={s}&client_secret={s}&grant_type=client_credentials",
        .{ client_id, scope, client_secret },
    );
    defer allocator.free(body);

    // Parse the URI
    const uri = try std.Uri.parse(token_url);

    // Create buffer for server headers
    var server_header_buffer: [4092]u8 = undefined;

    // Initialize the request with proper headers
    var req = try client.open(.POST, uri, .{
        .server_header_buffer = &server_header_buffer,
        .headers = .{
            .content_type = .{ .override = "application/x-www-form-urlencoded" },
            .host = .{ .override = "login.microsoftonline.com:443" },
        },
        .extra_headers = &.{.{ .name = "Accept", .value = "application/json" }},
    });
    defer req.deinit();

    // Set content length
    req.transfer_encoding = .{ .content_length = body.len };

    // Send the request
    try req.send();

    // Write the body
    try req.writer().writeAll(body);
    try req.finish();

    // Wait for response
    try req.wait();

    // Read response
    var response_buffer: [4096]u8 = undefined;
    const read_amount = try req.reader().read(&response_buffer);

    if (req.response.status != .ok) {
        return OAuthError.RequestFailed;
    }

    // Parse the JSON response using parseFromSlice
    const parsed = try json.parseFromSlice(
        OAuthResponse,
        allocator,
        response_buffer[0..read_amount],
        .{},
    );
    defer parsed.deinit();

    // Create the secure token
    return try OAuthToken.init(
        allocator,
        parsed.value.access_token,
        parsed.value.token_type,
        parsed.value.expires_in,
        parsed.value.ext_expires_in,
    );
}
