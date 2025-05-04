# HTTP Request Capture & Replay Tool

A tool for capturing HTTP requests, storing them in a PostgreSQL database, and replaying them later with optional authentication credentials.

## Features

- **Capture Mode**: Run as a server to receive and store HTTP requests
- **Replay Mode**: Replay stored requests with optional authentication tokens
- **Proxy Support**: Route replayed requests through Burp Suite, Caido, or other proxies
- **Authentication Testing**: Override cookies and CSRF tokens during replay

## Installation

1. Ensure you have Go 1.16+ installed
2. Clone this repository
3. Install dependencies:
   ```
   go get -u gorm.io/gorm
   go get -u gorm.io/driver/postgres
   go get -u gorm.io/datatypes
   ```

## Usage

### Prerequisites

Set your PostgreSQL database URL as an environment variable:

```bash
export DATABASE_URL="postgres://username:password@localhost:5432/dbname?sslmode=disable"
```

### Capture Mode

Run the server to capture requests:

```bash
go run main.go -mode serve
```

This starts an HTTP server on port 8081. To capture a request, send a POST request to `/receive` with:

```json
{
  "data": "base64_encoded_raw_http_request"
}
```

The base64-encoded data should be a complete raw HTTP request including method, path, headers, and body.

### Replay Mode

Replay captured requests (optionally through a proxy):

```bash
go run main.go -mode replay -cookies "session=token" -csrf "csrf_token" -proxy "http://127.0.0.1:8080"
```

#### Command-line Arguments

- `-mode`: Operation mode (`serve` or `replay`)
- `-cookies`: Cookie string for authentication during replay
- `-csrf`: CSRF token value for replay
- `-proxy`: Proxy address (defaults to http://127.0.0.1:8080)

## How It Works

### Capture Flow

1. HTTP server receives base64-encoded raw HTTP request
2. Server decodes the request and parses it into components
3. Request details are stored in PostgreSQL database

### Replay Flow

1. Tool loads all saved requests from database
2. For each request:
   - Original headers are preserved
   - Optional cookies and CSRF tokens are injected
   - Request is forwarded through configured proxy
   - Response status is logged

## Database Schema

The tool uses GORM to automatically create and manage the following schema:

```
SavedRequest
- ID (uint, primary key)
- Method (string)
- Scheme (string)
- Host (string)
- Path (string)
- Query (string)
- Headers (JSON)
- Body (string)
- CreatedAt (timestamp)
```

## Use Cases

- Capturing and replaying auth-protected requests
- Security testing with token replacement
- Integration with security tools via proxy support
- Analyzing request patterns

## License

MIT License (or specify your preferred license)
