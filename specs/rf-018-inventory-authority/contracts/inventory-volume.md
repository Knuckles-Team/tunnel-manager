# Inventory source and volume contract

## Source identity

The sole automatic source is the operator-selected XDG configuration file:

```text
$XDG_CONFIG_HOME/agent-utilities/inventory.yml
```

`XDG_CONFIG_HOME` is resolved for the executing operator or supplied as an explicit deployment input. The relative path and `.yml` basename are fixed. `inventory.yaml`, a checkout file, image seed, service-local document, and runtime cache are not alternative sources. A source receipt includes the normalized path, content digest, file type, selection mode, and validation result; it excludes contents and secret values.

## Runtime projection

| Field | Contract |
| --- | --- |
| Host source | Exactly the resolved `agent-utilities/inventory.yml` under the selected operator XDG config home. |
| Container target | `/etc/agent-utilities/inventory.yml` in an inventory-reading container. This is a mount target, not the application-level authority. |
| Mode | Read-only file bind (`:ro` in Compose or `readOnly: true` in Kubernetes) and no writable overlay at the target. |
| Startup | Validate source existence/type, mount visibility, selected digest, and read permission before reporting inventory readiness. |
| Failure | Missing/mismatched source, wrong basename, writable projection, or unreadable target prevents inventory-dependent service readiness. Do not use a package seed or another path. |

Container runtimes may use different host mount syntax, but they must preserve the logical source, target, digest, and write-denial behavior. The deployment owner supplies `HOST_XDG_CONFIG_HOME` or an equivalent typed XDG root. No repository stores an operator-specific absolute host path in a public manifest.

## Consumer contract

`container-manager-mcp` reads the same projected source and does not manage a copy. A consumer can transform inventory metadata into a derived view, but must carry the source digest and may not write back through its projection. A cache with no matching source digest is stale and must not be used as the current inventory. An explicit local/offline replay file is never advertised as serving inventory.
