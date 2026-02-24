# Build stage
FROM golang:1.24.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 go build -o /app/server ./cmd/server/main.go

# Run stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/server .
COPY --from=builder /app/config.toml .

# Create storage and data directories
RUN mkdir -p /app/storage /app/data

EXPOSE 8070

# Set environment variables if needed
# ENV DATABASE_URL=libsql:/app/data/vayload_registry.db

CMD ["./server"]
