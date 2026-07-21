# Configuration, trust, and privacy

This page is the operator contract for `tunnel-manager`. Package-specific endpoint,
authentication, tool-toggle, and model settings remain documented in the
repository README and the installed command's `--help` output. Every runtime
read goes through the Agent Utilities configuration boundary (`AgentConfig` and
its live `setting` accessor), so explicit process values and XDG `config.json`
values use the same resolution rules. They do not belong in source, packaged
skill content, traces, or generated reports.

## Capability configuration

The current capability surface is defined by three versioned artifacts:

- the action-routed MCP tools described in the README and `docs/usage.md`;
- the compact canonical skill plus any specialist `WORKFLOW.md` procedures;
- `connector_manifest.yml` and its ontology, mappings, shapes, fixtures,
  migrations, tool-schema fingerprints, and certification metadata.

Treat those artifacts as a unit during release and deployment. Do not enable a
skill whose certification or tool-schema fingerprint does not match the
installed package. Use the compact/intent-oriented tool surface for delegated
agents; expose verbose per-operation tools only for compatibility or debugging.

## Runtime values and secrets

- Supply service endpoints, tenant identifiers, credentials, and model keys
  through environment variables or a mounted secret provider.
- SSH password authentication accepts only an opaque `TUNNEL_PASSWORD_REF` or
  `password_ref` using `env://`, `vault://`, `secret://`, or `sqlite://`.
  Literal passwords in MCP arguments, environment variables, or inventory YAML
  are rejected before a connection is attempted.
- Use non-personal agent aliases and opaque tenant/correlation identifiers.
- Keep developer directories, workstation names, and deployment hostnames out
  of checked-in configuration.
- Keep MCP listeners and SSH local forwards on loopback. Put an authenticated,
  policy-enforcing gateway in front when remote access is required.
- Enable optional agent, embedding, evolution, or observability features only
  when their dependencies and backends are configured and healthy.

The checked-in examples use `localhost` for loopback-only development and
`example.invalid` for replaceable network endpoints. Neither value is a
production default.

## SSH server identity and execution limits

Every synchronous connection uses Paramiko `RejectPolicy`; every asynchronous
connection passes an explicit, securely owned `known_hosts` file to AsyncSSH.
There is no trust-on-first-use or unknown-host-key opt-in. Populate and review
host keys out of band before connecting. `ssh-keyscan` output is not trusted by
Tunnel Manager because the scan itself does not authenticate a server.

Use `TUNNEL_KNOWN_HOSTS` for the doctor check and `known_hosts_file` per inventory
entry when the default SSH trust file is not appropriate. Private keys must be
regular, non-symlink files with owner-only permissions on POSIX systems.

The following deployment inputs can tune resource caps only within hard safety
ranges enforced by the runtime:

| Variable | Default | Enforced maximum |
|---|---:|---:|
| `TUNNEL_MAX_COMMAND_CHARS` | 65,536 | 262,144 |
| `TUNNEL_MAX_OUTPUT_BYTES` | 1 MiB | 16 MiB |
| `TUNNEL_MAX_TRANSFER_BYTES` | 256 MiB | 2 GiB |
| `TUNNEL_MAX_FLEET_HOSTS` | 1,000 | 10,000 |
| `TUNNEL_MAX_CONCURRENCY` | 64 | 256 |

Connection, authentication, command, and key-generation operations also have
bounded timeouts and retry counts. Run `tunnel-manager-doctor` before deployment;
it resolves the same Agent Utilities configuration boundary as the runtime and
reports security readiness plus endpoint, inventory, identity, proxy, KG-ingest,
and health-feature presence. Its JSON contains booleans and numeric limits only,
never configured hosts, paths, commands, or secret references.

Typed file-management operations quote remote paths and patterns before shell
execution, reject unsafe owner/mode values, cap path lists at 64, cap search and
watch results at 10,000, and cap watch duration at one hour. Uploads reject local
symlinks; downloads use an owner-only temporary file followed by an atomic
replace so a partial transfer cannot clobber the requested destination.

## TLS trust

Certificate verification is required. For a private certificate authority,
mount a PEM bundle containing the required intermediate and root certificates,
then configure the client environment with `SSL_CERT_FILE` and, for
Requests-compatible clients, `REQUESTS_CA_BUNDLE`. When `uvx` must use the
native platform trust store while resolving packages, set `UV_NATIVE_TLS=true`.

Do not disable verification to work around an incomplete server chain. Keep CA
bundle locations environment-configured and stable for the runtime; never embed
a workstation path or certificate material in MCP configuration.

## Privacy and data governance

The default observability posture is metadata-only. Do not persist prompts,
message bodies, tool inputs/results, document content, raw traces, credentials,
local paths, hostnames, or personal identity unless an approved data contract
explicitly requires it. Keep Langfuse or OTLP content capture disabled unless a
reviewed retention and access policy authorizes it.

When connector ingestion is enabled, each change must carry tenant, ACL,
classification, retention, provenance, and checkpoint/delta metadata. Reject or
quarantine records that cannot satisfy that contract; never silently widen a
tenant scope. Logs and reports should contain counts, status, and opaque
references only.

## Deployment verification

1. Validate the capability bundle and skill metadata against the installed tool
   schemas.
2. Confirm required secrets are present without printing their values.
3. Run `tunnel-manager-doctor` and provision verified SSH host keys before any
   connection or mesh operation.
4. Verify the complete TLS chain with certificate verification enabled.
5. Exercise health/readiness and one least-privilege read operation.
6. Confirm traces arrive under the expected opaque tenant/run identifiers and
   contain no captured content.
7. Record only sanitized pass/fail evidence and version identifiers.
