# Zig Azure KeyVault Client

A lightweight, secure Azure Key Vault client written in Zig. This project provides a simple interface for interacting with Azure Key Vault, implementing secure token handling and key vault operations.

## Features

- Secure OAuth2 token handling with memory safety
- Key Vault operations:
  - List all secrets
  - Get specific secret values
  - Set secret values
- Memory-safe implementation with proper cleanup
- Optional React-based UI demo included

## Prerequisites

- Zig 0.13.0
- Azure subscription
- Azure Key Vault instance
- Application registered in Azure Active Directory with the following:
  - Client ID
  - Client Secret
  - Tenant ID
  - Key Vault access permissions

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/zig-azure-keyvault.git
cd zig-azure-keyvault
```

2. Build the project:
```bash
zig build
```

## Configuration

Create a configuration with your Azure credentials:

```zig
const client_id = "your-client-id";
const client_secret = "your-client-secret";
const tenant_id = "your-tenant-id";
const vault_name = "your-vault-name";
const api_version = "7.3";
```

## Usage

### Basic Example

```zig
const std = @import("std");
const azure_auth = @import("azure_auth.zig");
const keyvault = @import("azure_keyvault.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // Get OAuth token
    var token = try azure_auth.getOAuthToken(allocator, client_id, client_secret, tenant_id);
    defer token.deinit();

    // List secrets
    const secret_list = try keyvault.list_secrets(allocator, token.secure_token, vault_name, api_version);
    defer secret_list.deinit(allocator);

    // Get a specific secret
    const secret = try keyvault.get_secret(allocator, token.secure_token, vault_name, "my-secret", api_version);
    defer secret.deinit(allocator);
}
```

### API Reference

#### `azure_auth.getOAuthToken`
Securely obtains an OAuth token from Azure Active Directory.

#### `keyvault.list_secrets`
Lists all secrets in the specified vault.

#### `keyvault.get_secret`
Retrieves a specific secret by name.

#### `keyvault.set_secret`
Sets a secret value in the vault.

## Error Handling

The library uses Zig's error union type system to handle various error conditions:

```zig
pub const KeyVaultError = error{
    RequestFailed,
    InvalidResponse,
    SecretNotFound,
    AuthenticationFailed,
    InvalidRequest,
};
```

Error handling example:
```zig
const secret = keyvault.get_secret(allocator, token.secure_token, vault_name, "missing-secret", api_version) catch |err| {
    switch (err) {
        KeyVaultError.SecretNotFound => {
            // Handle missing secret
        },
        KeyVaultError.AuthenticationFailed => {
            // Handle authentication failure
        },
        else => {
            // Handle other errors
        },
    }
};
```

## Security Considerations

1. **Token Security**
   - Tokens are stored in secure memory buffers
   - Memory is zeroed before deallocation
   - Timing-safe comparisons are used for token verification

2. **Memory Safety**
   - All allocations are tracked and properly freed
   - Sensitive data is explicitly cleared from memory
   - No global state or static buffers are used

3. **Best Practices**
   - Use environment variables or secure configuration management for credentials
   - Implement proper error handling for all operations
   - Regularly rotate client secrets
   - Use the principle of least privilege when assigning Key Vault access permissions

4. **Known Limitations**
   - Buffer sizes are fixed for HTTP responses (8192 bytes)
   - No automatic token refresh implementation
   - Single-threaded operation only

## Demo UI

A React-based demo UI is included in the `ui` directory. This is for demonstration purposes only and should not be used in production without proper security review and implementation.

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## Disclaimer

This is a proof of concept implementation. While care has been taken to implement security best practices, it has not undergone a security audit and should be reviewed thoroughly before use in production environments.