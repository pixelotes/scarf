# --- Stage 1: Build ---
# Use the official Go image with an Alpine base to keep this stage small.
FROM golang:1.25-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Install build dependencies
RUN apk --no-cache add git ca-certificates

# Copy go.mod and go.sum to leverage Docker's build cache for dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application, creating a static binary and stripping debug info to reduce size.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/scarf .

# --- Stage 2: Final Image ---
# Use the minimal scratch base image.
FROM scratch

# Copy ca-certificates from the builder stage so our app can make HTTPS requests.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/scarf .

# Copy the tracker definitions and the web UI assets
COPY definitions ./definitions
COPY web ./web

# Create a directory for the database file
COPY data ./data

# Expose the port the app runs on
EXPOSE 8080

# The command to run when the container starts
CMD ["./scarf"]