<!-- mcp-name: io.github.AIops-tools/symantec-edr-aiops -->

# Symantec Endpoint Detection and Response (on-premises) AIops

Independent audited MCP server, CLI and skill for on-premises EDR investigations, entities, threat feeds, policy lists and sandbox results. This initial release exposes 20 read-only tools. MCP and CLI call the same governed functions; API credentials remain in environment variables, TLS verification is on, and every call records a local audit event.

> Community-maintained project. Not affiliated with or endorsed by Broadcom or Symantec; product names are their owners’ trademarks.

## Configure

```sh
export SYMANTEC_EDR_URL="..."
export SYMANTEC_EDR_CLIENT_ID="..."
export SYMANTEC_EDR_CLIENT_SECRET="..."
```

`SYMANTEC_EDR_URL` must be the on-premises appliance HTTPS origin (including port if needed, without a path). Optional `SYMANTEC_EDR_CA_BUNDLE` points to a trusted CA bundle; `SYMANTEC_EDR_TIMEOUT` defaults to 30 seconds. Audit state defaults to `~/.symantec-edr-aiops/` and can be relocated with `SYMANTEC_EDR_AIOPS_HOME`.

See the [operations catalog](docs/OPERATIONS.md) for the complete tool list, scope and deferred operations.

## Use

```sh
uvx --from symantec-edr-aiops==0.1.0 symantec-edr-aiops appliances
uvx --from symantec-edr-aiops==0.1.0 symantec-edr-aiops-mcp
```

Search incidents and events over at most 30 days, audit events over at most seven days; use the returned opaque next cursor for pagination. See [verification](docs/VERIFICATION.md) for the exact evidence and unverified live behavior. No state-changing operations are exposed.
