# Vsay Agent Backend

Backend server for Vsay Agent, providing gRPC interface for agents and HTTP API for the frontend.

## Features
- **TLS/HTTPS Support**: Secure communication with TLS encryption for both HTTP and gRPC
- **WebSocket over TLS (WSS)**: Secure terminal sessions
- gRPC Server for bidirectional Agent communication (Command execution, Terminal streaming)
- HTTP/HTTPS API for frontend integration
- MongoDB for data persistence
- JWT Authentication
- Production-ready logging configuration

## Getting Started

### Prerequisites
- Go 1.22+
- Docker & Docker Compose
- OpenSSL (for generating certificates)

### TLS Certificate Setup

For development, self-signed certificates are provided in the `certs/` directory:
- `server-cert.pem`: TLS certificate
- `server-key.pem`: Private key

To regenerate certificates:
```bash
cd certs
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Vsay/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

For production, use certificates from a trusted CA (Let's Encrypt, etc.).

### Environment Configuration

Create/update `.env` file:
```bash
# Database
MONGO_URI=mongodb://localhost:27017

# Authentication
JWT_SECRET=your_super_secret_jwt_key

# TLS Configuration
TLS_ENABLED=true
TLS_CERT_FILE=./certs/server-cert.pem
TLS_KEY_FILE=./certs/server-key.pem
HTTPS_PORT=8443
GRPC_TLS_ENABLED=true

# Logging
GIN_MODE=release

# Reconciler
RECONCILER_INTERVAL=1m
OFFLINE_TIMEOUT=2m

# Optional: Cloudinary for avatar uploads
CLOUDINARY_URL=cloudinary://...
```

### Docker Build

#### Build the image
```bash
docker build -t amiteshhsingh/vsay-backend:v1.0.0 .

### for multiarch
docker build --platform linux/amd64,linux/arm64 -t amiteshhsingh/vsay-backend:v1.0.0 .
```

#### Build for Kubernetes deployment
```bash
# Tag with version for registry (replace with your registry)
docker build --platform linux/amd64,linux/arm64 -t amiteshhsingh/vsay-backend:v1.0.0 .

# Examples for different registries:

# Docker Hub
docker build --platform linux/amd64,linux/arm64 -t amiteshhsingh/vsay-backend:v1.0.0 .
docker push amiteshhsingh/vsay-backend:v1.0.0

# AWS ECR
docker build --platform linux/amd64,linux/arm64 -t 123456789.dkr.ecr.us-east-1.amazonaws.com/vsay-backend:v1.0.0 .
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com
docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/vsay-backend:v1.0.0

# Google GCR
docker build --platform linux/amd64,linux/arm64 -t gcr.io/project-id/vsay-backend:v1.0.0 .
docker push gcr.io/project-id/vsay-backend:v1.0.0

# GitHub Container Registry
docker build --platform linux/amd64,linux/arm64 -t ghcr.io/username/vsay-backend:v1.0.0 .
docker push ghcr.io/username/vsay-backend:v1.0.0

# Multi-arch build (for mixed k8s clusters)
```

#### Run with Docker Compose (Recommended)
```bash
docker-compose up -d
```

This starts both the backend and MongoDB. Services available at:
- HTTP API: `http://localhost:8080`
- gRPC: `localhost:8081`
- MongoDB: `localhost:27017`

#### Run standalone container
```bash
docker run -d \
  --name vsay-backend \
  -p 8080:8080 \
  -p 8081:8081 \
  -e MONGO_URI=mongodb://host.docker.internal:27017 \
  -e JWT_SECRET=your-secret-key \
  vsay-backend
```

#### With TLS enabled
```bash
docker run -d \
  --name vsay-backend \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8081:8081 \
  -v $(pwd)/certs:/app/certs:ro \
  -e MONGO_URI=mongodb://host.docker.internal:27017 \
  -e JWT_SECRET=your-secret-key \
  -e TLS_ENABLED=true \
  -e GRPC_TLS_ENABLED=true \
  vsay-backend
```

#### Useful commands
```bash
# View logs
docker logs -f vsay-backend

# Check health status
docker inspect --format='{{.State.Health.Status}}' vsay-backend

# Stop and remove
docker-compose down
```

### Running Locally

1. Start MongoDB:
   ```bash
   docker run -d -p 27017:27017 mongo
   ```

2. Run Server:
   ```bash
   go run cmd/server/main.go
   ```

The server will start:
- **HTTPS Server**: `https://localhost:8443` (when TLS_ENABLED=true)
- **HTTP Redirect**: `http://localhost:8080` → redirects to HTTPS
- **gRPC Server**: `localhost:8081` (with TLS when GRPC_TLS_ENABLED=true)

### Disabling TLS (Development Only)

To run without TLS:
```bash
# In .env file
TLS_ENABLED=false
GRPC_TLS_ENABLED=false
```

## Security Features

### TLS Configuration
- **HTTPS**: All HTTP traffic encrypted with TLS 1.2+
- **WSS**: WebSocket connections upgraded to secure WSS
- **gRPC with TLS**: Agent communication encrypted
- **Auto HTTP→HTTPS Redirect**: Automatically redirects HTTP to HTTPS

### Logging
- **Production Mode**: `GIN_MODE=release` disables debug logs
- **Custom Logger**: Structured logging with Zap
- **No Request Logging**: HTTP request logs suppressed for cleaner output
- **Minimal Output**: Only application logs (no route debugging)

## Development

### Proto Generation
```bash
protoc -Iproto --go_out=proto --go_opt=paths=source_relative \
  --go-grpc_out=proto --go-grpc_opt=paths=source_relative \
  proto/common/types.proto proto/agent/agent.proto
```
*Note: Ensure `proto/agent/v1` and `proto/common/v1` directories exist.*

## API Endpoints

### Public Endpoints
- `POST /api/signup`: Create account
- `POST /api/login`: Login
- `POST /api/auth/refresh`: Refresh JWT token
- `GET /api/terminal/:agent_id/ws`: WebSocket terminal connection (WSS)

### Protected Endpoints (Requires Bearer Token)
- `GET /api/dashboard/stats`: Dashboard statistics
- `GET /api/dashboard/recent-machines`: Recent machines
- `GET /api/dashboard/recent-activity`: Recent activity
- `GET /api/machines`: List machines
- `GET /api/machines/:agent_id`: Machine details
- `GET /api/machines/:agent_id/logs`: Machine logs
- `POST /api/machines/:agent_id/command`: Execute command
- `GET /api/terminal/sessions`: List terminal sessions
- `DELETE /api/terminal/sessions/:session_id`: Delete session
- `GET /api/profile`: User profile
- `POST /api/profile/regenerate-api-key`: Regenerate API key
- `POST /api/profile/reset-password`: Reset password
- `POST /api/profile/upload-avatar`: Upload avatar

## Agent Configuration

When configuring the agent, use:
- **With TLS**: `https://localhost:8443` (gRPC will use `localhost:8081` with TLS)
- **Without TLS**: `http://localhost:8080` (gRPC will use `localhost:8081` without TLS)

The agent will automatically configure gRPC TLS based on the `Server.TLS` setting in its config.

## Browser Certificate Warnings

When using self-signed certificates in development:
1. Browser will show "Your connection is not private" warning
2. Click "Advanced" → "Proceed to localhost (unsafe)"
3. Or add certificate to system trust store (macOS/Linux/Windows)

For production, always use certificates from a trusted CA.
