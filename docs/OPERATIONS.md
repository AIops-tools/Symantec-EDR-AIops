# Operations catalog

All listed operations are read-only and route through the same audited MCP/CLI implementation. A tool count describes interface coverage, not live verification.

## Appliance and activity

| MCP tool | Purpose |
|---|---|
| `edr_appliances` | Read EDR management appliance metadata. |
| `edr_incidents` | Search incidents over at most 30 days. |
| `edr_events` | Search events over at most 30 days. |
| `edr_audit_events` | Search audit events over at most 7 days. |
| `edr_incident_events` | Search incident events over at most 30 days. |
| `edr_incident_lineage_events` | Search incident lineage events. |
| `edr_system_activities` | Search system activities over at most 7 days. |

## Entities and threat feeds

| MCP tool | Purpose |
|---|---|
| `edr_entities` | Search EDR entities. |
| `edr_file_entities` | Search file entities. |
| `edr_file_entity` | Read one file entity by SHA-256. |
| `edr_adversary_actors` | Search adversary actor feed. |
| `edr_adversary_files` | Search adversary file feed. |
| `edr_adversary_networks` | Search adversary network feed. |

## Policies and sandbox results

| MCP tool | Purpose |
|---|---|
| `edr_allow_list` | List allow policies. |
| `edr_deny_list` | List deny policies. |
| `edr_sandbox_command` | Read sandbox command status. |
| `edr_sandbox_verdict` | Read sandbox verdict by SHA-256. |
| `edr_sandbox_activities` | Read sandbox activities. |
| `edr_sandbox_events` | Read sandbox events. |
| `edr_sandbox_patterns` | Read sandbox patterns. |

## Limits and next work

Command issuance and sandbox detonation change server state. Association query response examples are too weak for a reliable page contract. Those operations remain excluded until a real appliance can verify outcomes.

API paths and response examples are from the official Broadcom documentation listed below. No tenant or appliance has been supplied for live verification; consult [VERIFICATION.md](VERIFICATION.md).

- [appliance_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/appliance_resource.md)
- [incidents_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/incidents_resource.md)
- [events_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/events_resource.md)
- [auditEvents_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/auditEvents_resource.md)
- [incident_events_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/incident_events_resource.md)
- [system_activities_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/system_activities_resource.md)
- [entities_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/entities_resource.md)
- [data_feeds_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/data_feeds_resource.md)
- [deny_list_policy_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/deny_list_policy_resource.md)
- [sandbox_resource](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/sandbox_resource.md)
