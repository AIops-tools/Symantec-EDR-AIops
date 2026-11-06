# Verification

## Official API contracts reviewed

- [oauth_token_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/oauth_token_resource.md)
- [appliance_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/appliance_resource.md)
- [incidents_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/incidents_resource.md)
- [events_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/events_resource.md)
- [auditEvents_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/auditEvents_resource.md)

The auth scheme, listed paths, query bounds and response examples informed the read-only implementation. An official schema example is not a substitute for a live response.

## Local validation

- Contract-shaped HTTP mock tests and inherited governance tests passed (40 pytest tests). Ruff passed; Bandit found 0 Medium+ issues. The 0.1.0 wheel installed in an external virtual environment and its MCP server imported from site-packages. All five handbook gates passed over 36 tools.
- The vendored governance harness uses the same path for MCP and CLI. Query-only POST routes are explicitly allowlisted.

## Not yet verified

- No live Symantec Endpoint Detection and Response (on-premises) tenant/appliance or test credentials have been supplied. Authentication, privileges, response shape, pagination and real operational behavior remain unverified against a server.
- No write or undo workflow is exposed. Any write additions require live result, audit and rollback proof before release.

This tool targets the documented on-premises EDR API and is separate from SES Cloud. Broadcom reports S550 hardware end of life and directs customers to EDR 4.12 on a virtual appliance: https://knowledge.broadcom.com/external/article/433324/symantec-edr-s550-hardware-endoflife-ann.html. Neither appliance form has been tested here.

## Expanded coverage review

The [operations catalog](OPERATIONS.md) lists every implemented tool, source API topic and excluded operation. New read paths have contract-shaped HTTP tests. Public API examples may differ from a real tenant; all added paths remain live-unverified.

All API responses above 16 MiB fail explicitly before JSON parsing to keep unexpected unbounded results out of an agent context. This does not replace server-side pagination; unpaged endpoints report measured output truncation.
