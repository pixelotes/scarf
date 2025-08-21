# --- Stage 1: Build ---
# Use the official Go image with an Alpine base to keep this stage small.
FROM golang:1.25-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Install build dependencies
RUN apk --no-cache add git

# Copy go.mod and go.sum to leverage Docker's build cache for dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application, creating a static binary and stripping debug info to reduce size.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/scarf .

# --- Stage 2: Final Image ---
# Use the minimal Alpine base image.
FROM alpine:latest

# Add ca-certificates so our app can make HTTPS requests to trackers
RUN apk --no-cache add ca-certificates

# Set the working directory
WORKDIR /app

# Create a non-root user for better security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the compiled binary from the builder stage
COPY --from=builder /app/scarf .

# Copy the tracker definitions and the web UI assets
COPY definitions ./definitions
COPY web ./web

# Create a directory for the database file and set permissions
RUN mkdir /app/data && chown -R appuser:appgroup /app/data
# Set permissions for the whole app directory
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 8080

# The command to run when the container starts
CMD ["./scarf"]
