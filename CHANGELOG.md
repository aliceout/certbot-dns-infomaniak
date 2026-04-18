# Changelog

## 1.0.0 (breaking)

- Migrate to Infomaniak API v2 (`/2/zones/{zone}/records`).
- Replace the blind `time.sleep(propagation_seconds)` wait with polling of
  `GET /2/zones/{zone}/records/{id}/check`. The configured
  `propagation_seconds` still applies as a safety buffer if the check endpoint
  times out.
- Token scopes required: `domain:read`, `dns:read`, `dns:write`. Legacy v1
  tokens must be regenerated.
- Track the record id returned by the `POST` and use it directly for cleanup,
  removing the fragile search-based lookup that could fail with
  `Record not found` after a successful issuance.
- Document the Infomaniak **Fast Anycast** option as a known blocker for
  `dns-01` (records are stored but never published on the name servers; see
  upstream issue #47).
