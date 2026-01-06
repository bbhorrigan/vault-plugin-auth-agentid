# GitHub Issues for vault-plugin-auth-agentid

This file contains issue templates ready to be created in GitHub. Each issue is formatted for easy copy-paste or GitHub CLI usage.

---

## 🔒 Security Issues

### Issue #1: Enforce HTTPS for JWKS URLs

**Title:** Security: Enforce HTTPS for JWKS URLs in production

**Labels:** `security`, `enhancement`

**Description:**
Currently, the plugin accepts any URL scheme for JWKS fetching, including HTTP. This is a security risk as JWKS data could be intercepted or modified in transit.

**Acceptance Criteria:**
- [ ] Add validation to reject non-HTTPS JWKS URLs
- [ ] Add a configuration option `allow_insecure_jwks` for development/testing (default: false)
- [ ] Log a warning when insecure URLs are used in dev mode
- [ ] Update documentation

**Priority:** High

---

### Issue #2: Add context support to HTTP requests for JWKS fetching

**Title:** Add context cancellation support to JWKS HTTP requests

**Labels:** `security`, `enhancement`

**Description:**
The `fetchJWKS` function creates an HTTP client but doesn't use the request context for cancellation. This could lead to hanging requests and resource leaks.

**Acceptance Criteria:**
- [ ] Use `http.NewRequestWithContext` for JWKS fetching
- [ ] Propagate context from the original request
- [ ] Add configurable timeout for JWKS requests
- [ ] Add tests for context cancellation

**Priority:** High

---

### Issue #3: Make JWKS cache TTL configurable

**Title:** Make JWKS cache TTL configurable

**Labels:** `enhancement`

**Description:**
The JWKS cache TTL is hardcoded to 5 minutes. Operators should be able to configure this value based on their security requirements and key rotation policies.

**Acceptance Criteria:**
- [ ] Add `jwks_cache_ttl` configuration option
- [ ] Default to 300 seconds (5 minutes)
- [ ] Allow 0 to disable caching
- [ ] Update documentation

**Priority:** High

---

## 🏗️ Architecture Issues

### Issue #4: Implement role-based access control

**Title:** Feature: Add role-based access control

**Labels:** `enhancement`, `feature`

**Description:**
The README mentions roles but they are not implemented. Roles provide more granular control over authentication policies and token parameters.

**Acceptance Criteria:**
- [ ] Create `path_roles.go` with CRUD operations
- [ ] Support `bound_subjects`, `bound_issuers`, `bound_audiences`
- [ ] Support `token_policies`, `token_ttl`, `token_max_ttl`
- [ ] Update login path to optionally use roles
- [ ] Add comprehensive tests
- [ ] Update documentation

**Priority:** High

---

### Issue #5: Add bound claims support

**Title:** Feature: Add bound claims validation

**Labels:** `enhancement`, `feature`

**Description:**
Allow administrators to require specific claim values for authentication. This enables more fine-grained access control based on JWT claims.

**Acceptance Criteria:**
- [ ] Add `bound_claims` to role configuration
- [ ] Support exact match validation
- [ ] Support glob pattern matching for claim values
- [ ] Add tests for bound claims validation
- [ ] Update documentation

**Priority:** Medium

---

### Issue #6: Add clock skew tolerance configuration

**Title:** Add configurable clock skew tolerance for JWT validation

**Labels:** `enhancement`

**Description:**
JWT validation can fail due to clock differences between servers. Add a configurable leeway for `exp` and `nbf` claim validation.

**Acceptance Criteria:**
- [ ] Add `clock_skew_leeway` configuration option
- [ ] Default to 60 seconds
- [ ] Apply leeway to both `exp` and `nbf` validation
- [ ] Add tests for clock skew handling
- [ ] Update documentation

**Priority:** Medium

---

## 🧪 Testing Issues

### Issue #7: Add tests for RSA and EdDSA key types

**Title:** Add comprehensive tests for RSA and EdDSA key types

**Labels:** `testing`

**Description:**
Current tests only cover EC (P-256) keys. Add tests for RSA and EdDSA (Ed25519) to ensure all supported algorithms work correctly.

**Acceptance Criteria:**
- [ ] Add RSA key generation and login tests
- [ ] Add EdDSA key generation and login tests
- [ ] Add tests for algorithm mismatch errors
- [ ] Test key parsing from both PEM and JWKS formats

**Priority:** Medium

---

### Issue #8: Add audience validation tests

**Title:** Add tests for audience claim validation

**Labels:** `testing`

**Description:**
Add tests to verify audience validation works correctly when `required_audience` is configured.

**Acceptance Criteria:**
- [ ] Test login with matching audience
- [ ] Test login with non-matching audience (should fail)
- [ ] Test login with multiple audiences (array)
- [ ] Test login when audience is not required

**Priority:** Medium

---

### Issue #9: Add integration tests with real Vault instance

**Title:** Add integration tests with real Vault instance

**Labels:** `testing`, `enhancement`

**Description:**
Add integration tests that run against a real Vault instance to catch issues that unit tests might miss.

**Acceptance Criteria:**
- [ ] Add `_integration_test.go` file
- [ ] Skip in short mode (`go test -short`)
- [ ] Test full plugin registration and authentication flow
- [ ] Add Docker Compose setup for test environment
- [ ] Document how to run integration tests

**Priority:** Low

---

## 📦 Build & DevOps Issues

### Issue #10: Add version information to binary

**Title:** Embed version information in binary

**Labels:** `enhancement`, `devops`

**Description:**
Embed build version, commit hash, and build time in the binary for easier debugging and version tracking.

**Acceptance Criteria:**
- [ ] Add version variables to main.go
- [ ] Update Makefile to inject version via ldflags
- [ ] Add `version` command or log version on startup
- [ ] Include git commit hash and build time

**Priority:** Medium

---

### Issue #11: Add Dockerfile for easy testing

**Title:** Add Dockerfile for development and testing

**Labels:** `enhancement`, `devops`

**Description:**
Add a Dockerfile that builds and runs Vault with the plugin pre-installed for easier development and testing.

**Acceptance Criteria:**
- [ ] Create Dockerfile
- [ ] Create docker-compose.yml for full dev environment
- [ ] Add documentation for Docker usage
- [ ] Include example configuration in Docker setup

**Priority:** Medium

---

### Issue #12: Add golangci-lint configuration

**Title:** Add .golangci.yml for consistent linting

**Labels:** `enhancement`, `devops`

**Description:**
Add a golangci-lint configuration file to enforce consistent code quality and catch potential issues.

**Acceptance Criteria:**
- [ ] Create `.golangci.yml` with appropriate linters
- [ ] Enable security-focused linters (gosec)
- [ ] Fix any existing linting issues
- [ ] Add lint check to Makefile
- [ ] Document linting requirements

**Priority:** Low

---

## 📝 Code Quality Issues

### Issue #13: Add request ID logging for debugging

**Title:** Add request ID logging for improved debugging

**Labels:** `enhancement`

**Description:**
Add request ID and correlation information to log messages for easier debugging and troubleshooting.

**Acceptance Criteria:**
- [ ] Log request ID on login attempts
- [ ] Log agent identity information (sanitized)
- [ ] Add structured logging fields
- [ ] Document log format

**Priority:** Low

---

### Issue #14: Consider using go-jose library for JWK parsing

**Title:** Refactor: Use go-jose library for JWK parsing

**Labels:** `refactor`, `enhancement`

**Description:**
Replace manual JWK parsing with the go-jose library (already a transitive dependency) for better edge case handling and maintainability.

**Acceptance Criteria:**
- [ ] Replace manual JWK parsing with go-jose
- [ ] Ensure all key types still work
- [ ] Add/update tests for edge cases
- [ ] Verify no breaking changes

**Priority:** Low

---

## 📚 Documentation Issues

### Issue #15: Add CHANGELOG.md

**Title:** Add CHANGELOG.md for version tracking

**Labels:** `documentation`

**Description:**
Add a CHANGELOG.md file to track changes between versions, making it easier for users to understand what changed when upgrading.

**Acceptance Criteria:**
- [ ] Create CHANGELOG.md following Keep a Changelog format
- [ ] Document existing features as initial release
- [ ] Add guidance for maintaining changelog going forward

**Priority:** Low

---

### Issue #16: Add troubleshooting section to README

**Title:** Add troubleshooting section to documentation

**Labels:** `documentation`

**Description:**
Add a troubleshooting section to help users diagnose common issues.

**Acceptance Criteria:**
- [ ] Document common error messages and solutions
- [ ] Add debugging tips
- [ ] Include examples of correct configuration
- [ ] Add FAQ section

**Priority:** Low

---

### Issue #17: Add example token generation script

**Title:** Add helper script for generating test tokens

**Labels:** `documentation`, `enhancement`

**Description:**
Add a helper script that generates signed JWTs for testing the plugin.

**Acceptance Criteria:**
- [ ] Create script to generate test EC/RSA/EdDSA keys
- [ ] Create script to generate signed test tokens
- [ ] Document usage
- [ ] Add to examples/ directory

**Priority:** Low

---

## GitHub CLI Commands

To create these issues using the GitHub CLI, run:

```bash
# Issue #1
gh issue create --title "Security: Enforce HTTPS for JWKS URLs in production" \
  --label "security,enhancement" \
  --body "See GITHUB_ISSUES.md for full description"

# Issue #2
gh issue create --title "Add context cancellation support to JWKS HTTP requests" \
  --label "security,enhancement" \
  --body "See GITHUB_ISSUES.md for full description"

# ... etc
```

Or use the GitHub web interface to create issues with the descriptions above.


