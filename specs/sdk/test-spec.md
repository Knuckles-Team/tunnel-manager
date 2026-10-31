# CONN-TUNNEL-MANAGER-SDK test specification

Tests use synthetic credentials and mock transports. They need no network.

| Scenario | Requirements | Expected result |
|---|---|---|
| Secret references resolve through the SDK | `CONN-TUNNEL-MANAGER-SDK-R001` | A unit test resolves env:// and openbao:// references and rejects malformed ones |
| SDK floor and dependency set | `CONN-TUNNEL-MANAGER-SDK-R002` | pyproject.toml shows the floor and no requests pin |
| Production wiring | `CONN-TUNNEL-MANAGER-SDK-R003` | A test enters at the production entry point and reaches the wired call site. |
| Hot-path proof | `CONN-TUNNEL-MANAGER-SDK-R004` | The named integration test passes. |
| One wiring for every transport | `CONN-TUNNEL-MANAGER-SDK-R005` | stdio, no-auth HTTP and JWT HTTP use one actor path; 401 without a token; not-entitled refusal is the same 403 from both tools |
| One connection resolver | `CONN-TUNNEL-MANAGER-SDK-R005.1` | inventory group port is used, not 22; unknown alias is a 400 from both tools |
| Every tool on three transports | `CONN-TUNNEL-MANAGER-SDK-R005.2` | the 41 tool outcomes match across stdio, HTTP none and HTTP JWT against a real SSH host |
| Causes, native keys, confirm | `CONN-TUNNEL-MANAGER-SDK-R005.3` | failures carry `Type: message`; key generation needs no binary; `confirm=true` works without elicitation |
| Windows portability | `CONN-TUNNEL-MANAGER-SDK-R006` | with `os.fchmod`/`os.getuid` removed and `os.name` set to `nt`, files are hardened with `S_IREAD\|S_IWRITE`, inventory and key writes succeed, and no source calls `/usr/bin/ssh-keygen` |
