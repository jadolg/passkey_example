# Passkey Authentication Prototype

A demonstration web application implementing passwordless authentication using WebAuthn/Passkeys. Built with Go backend and vanilla HTML/CSS/JavaScript frontend.

> **Warning**: This is an AI-generated prototype for educational and demonstration purposes only. It is NOT suitable for production use. Security considerations such as proper secret management, HTTPS enforcement, rate limiting, and comprehensive input validation have not been fully implemented.

## Features

- Passwordless authentication using WebAuthn/Passkeys
- Trust on first contact registration (username + passkey only)
- JWT-based session management
- Multiple passkey support per user
- Passkey management (add, rename, delete)
- Protected dashboard page
- File-based user storage


## Requirements

- Go 1.25 or later
- A WebAuthn-compatible browser (Chrome, Firefox, Safari, Edge)
- A passkey-capable authenticator (security key, platform authenticator, or browser-based)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd passkey_example
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Run the server:
   ```bash
   go run main.go
   ```

4. Open http://localhost:8080 in your browser.

## Usage

### Registration

1. Navigate to the registration page
2. Enter a username
3. Click "Register with Passkey"
4. Complete the authenticator prompt (touch security key, use biometrics, etc.)
5. You will be redirected to the dashboard

### Login

1. Navigate to the login page
2. Enter your username
3. Click "Login with Passkey"
4. Complete the authenticator prompt
5. You will be redirected to the dashboard

### Managing Passkeys

From the dashboard, you can:
- Add additional passkeys (with custom names)
- Rename existing passkeys
- Delete passkeys (except the last one)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/register/begin` | Start registration ceremony |
| POST | `/api/register/finish` | Complete registration |
| POST | `/api/login/begin` | Start login ceremony |
| POST | `/api/login/finish` | Complete login |
| GET | `/api/user` | Get current user info (protected) |
| POST | `/api/logout` | Clear session |
| POST | `/api/passkey/add/begin` | Start adding new passkey (protected) |
| POST | `/api/passkey/add/finish` | Complete adding passkey (protected) |
| GET | `/api/passkeys` | List user passkeys (protected) |
| PUT | `/api/passkey` | Rename a passkey (protected) |
| DELETE | `/api/passkey` | Remove a passkey (protected) |

## Configuration

The following constants in `main.go` can be modified:

```go
const (
    jwtSecret   = "your-secret-key-change-in-production"  // JWT signing key
    jwtDuration = 24 * time.Hour                          // Token validity
    cookieName  = "auth_token"                            // Cookie name
)
```

WebAuthn configuration in `main()`:

```go
auth.Config{
    RPDisplayName: "Passkey Example",      // Display name shown to users
    RPID:          "localhost",            // Relying Party ID (domain)
    RPOrigins:     []string{"http://localhost:8080"},  // Allowed origins
}
```

## License

This prototype is provided as-is for educational purposes.
