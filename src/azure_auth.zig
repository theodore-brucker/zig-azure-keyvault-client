const std = @import("std");
const json = std.json;

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

pub const OAuthToken = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: u32,
    ext_expires_in: u32,

    pub fn deinit(self: *const OAuthToken, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        allocator.free(self.token_type);
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

    // Create owned copies of the strings
    return OAuthToken{
        .access_token = try allocator.dupe(u8, parsed.value.access_token),
        .token_type = try allocator.dupe(u8, parsed.value.token_type),
        .expires_in = parsed.value.expires_in,
        .ext_expires_in = parsed.value.ext_expires_in,
    };
}
