# Security

Report vulnerabilities privately to the repository maintainers. Do not paste API credentials, response bodies containing sensitive security data, or audit databases into public issues. TLS verification is enabled by default. Use an account with only the read privileges needed for these tools, and restrict local access to audit state. This preview contains no state-changing MCP or CLI operation.

The transport restricts query-only POST routes and rejects API responses above 16 MiB. Read results may still contain operational or personal data; grant the connecting account only needed privileges.
