# README.md
# BLS Signature Verification Circuit

This project implements a zero-knowledge proof circuit for BLS signature verification using the Gnark framework.

## Prerequisites

- Go 1.21 or later
- Make (optional, for build automation)

## Setup

1. Clone the repository
2. Initialize the Go module:
   ```bash
   go mod init bls-verify
   go mod tidy
   ```

## Build and Test

To build the project:
```bash
go build ./...
```

To run tests:
```bash
go test ./...
```

## Usage

1. Import the circuit package
2. Initialize the proving system
3. Create and verify proofs using actual BLS signature values