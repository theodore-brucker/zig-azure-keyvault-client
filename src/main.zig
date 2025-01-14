const std = @import("std");
const azure = @import("./azure_cli_auth.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const token = try azure.getOAuthToken(allocator, "760600a2-aa56-4ba2-b1be-1f54ced2feec", "1M58Q~y~Z5t1RUx9PVniI2XsrQ7Vz2HDdKcVWcfi", "ce1a7451-84f5-4eaa-bda7-ea1f54772c73");
    defer token.deinit(allocator);

    std.debug.print("Access Token: {s}\n", .{token.access_token});
    std.debug.print("Token Type: {s}\n", .{token.token_type});
    std.debug.print("Expires In: {d} seconds\n", .{token.expires_in});
}
