# CONN-TUNNEL-MANAGER-INVENTORY — Data model

Governing spec: [spec.md](spec.md).

## Hardware probe payload

The tool `tm_system_get_hardware` returns one object. Its schema name is `inventory-probe-system/v1`.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `inventory-probe-system/v1` |
| `reachable` | boolean | False when the host cannot be reached. Then no other field is present |
| `system.uuid`, `system.serial`, `system.manufacturer`, `system.model` | string or null | Firmware identity values |
| `os.name`, `os.version`, `os.kernel`, `os.architecture` | string | Operating system facts |
| `processors[]` | object | `socket` (integer), `model` (string), `cores` (integer), `threads` (integer) |
| `memory_modules[]` | object | `slot` (string), `size_bytes` (integer), `serial` (string or null), `model` (string or null) |
| `memory_total_bytes` | integer | Total memory |
| `storage_devices[]` | object | `name`, `model`, `serial`, `size_bytes`, `medium` in `hdd`, `ssd`, `nvme`, `other` |
| `network_interfaces[]` | object | `name`, `mac`, `speed_megabits`, `link` in `up`, `down`, `unknown` |
| `network_bonds[]` | object | `name`, `mode`, `members` (list of interface names) |
| `accelerators[]` | object | `kind` in `gpu`, `fpga`, `tpu`, `dpu`, `other`, `model`, `memory_bytes`, `serial`, `pci_address` |

No field holds a credential.
