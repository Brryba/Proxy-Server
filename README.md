## Technologies

- Java 21
- Maven
- Redis for caching
- BouncyCastle for certificate generation
- YAML for configuration
- Sockets
- Multithreading for working with multiple cliens concurrently

## Features

### Core Features
- HTTP/HTTPS request handling
- Man-in-the-Middle (MITM) capabilities
- Dynamic SSL certificate generation
- Redis-based response caching
- Domains blacklist
- Request logging
- YAML-based configuration

### MITM Implementation
- Generates dynamic CA certificate
- Creates on-the-fly certificates for each domain
- Performs SSL/TLS connection with both client and server

### Certificate Management
- Uses self-signed root sertificate
- Dynamic server certificate creation per domain
- Trust store management

### Caching System
- Redis as primary cache storage
- Requests & Responses are stored in cache
- HTTP headers analysis to choose caching strategy
