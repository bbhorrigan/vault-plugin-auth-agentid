# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Role-based access control**: New `role/` path for defining authentication roles with:
  - Bound claims validation (subjects, issuers, audiences, agent IDs)
  - Custom bound claims with glob pattern support
  - Role-specific token policies and TTLs
  - Intent restrictions per role
- **Enhanced security configuration**:
  - HTTPS enforcement for JWKS URLs (configurable via `allow_insecure_jwks`)
  - Configurable JWKS cache TTL (`jwks_cache_ttl`)
  - Configurable clock skew tolerance (`clock_skew_leeway`)
  - Configurable JWKS request timeout (`jwks_request_timeout`)
- **Improved HTTP handling**:
  - Context cancellation support for JWKS fetching
  - TLS 1.2 minimum version enforcement
  - Response body size limiting (1MB max)
  - Custom User-Agent header for JWKS requests
- **Better observability**:
  - Request ID logging for all authentication attempts
  - Detailed success/failure logging with agent identity
  - Role name included in authentication metadata
- **Docker support**:
  - Dockerfile for building containerized plugin
  - docker-compose.yml for development environment
  - Automated plugin registration in development mode
- **Build improvements**:
  - Version information embedded in binary (`-v` flag)
  - golangci-lint configuration for code quality
  - Multi-platform build with version info
- **Testing**:
  - RSA key authentication tests
  - EdDSA (Ed25519) key authentication tests
  - Audience validation tests
  - Role-based authentication tests
  - Algorithm mismatch tests
  - Comprehensive role validation tests

### Changed
- Improved error messages with more context
- JWKS cache now respects configurable TTL instead of hardcoded 5 minutes
- Clock skew validation now uses configurable leeway

### Security
- JWKS URLs now require HTTPS by default
- Added TLS 1.2 minimum version for JWKS fetching
- Limited JWKS response body to prevent memory exhaustion attacks

## [0.1.0] - Initial Release

### Added
- JWT/TraT/SIOP token verification
- JWKS support with URL fetching and static key configuration
- Support for RS256, ES256, and EdDSA signing algorithms
- Intent-based policy mapping
- DID (Decentralized Identifier) support
- MCP metadata tracking (tool_name, mcp_server)
- Configurable TTLs for issued tokens
- Trusted issuer configuration
- Audience validation

[Unreleased]: https://github.com/bbhorrigan/vault-plugin-auth-agentid/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bbhorrigan/vault-plugin-auth-agentid/releases/tag/v0.1.0


