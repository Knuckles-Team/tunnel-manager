# CONN-TUNNEL-MANAGER-CONNECTOR-CONTENT — Requirements

Governing spec: [spec.md](spec.md).

Each row is one requirement. A row names the file it touches and the test that proves it. The generator sets each row's state in `status.json`.

| ID | Requirement | Acceptance |
|---|---|---|
| `CONN-TUNNEL-MANAGER-CONNECTOR-CONTENT-R001` | **Default content.** `pyproject.toml` declares `tunnel-manager-mcp` as the single `scion_sdk.connector` entry point. The server lists the packaged `skill://` and `ontology://` resources and the packaged prompts with no `content=` argument. Caller chain: `tunnel-manager` in `pyproject.toml` runs `tunnel_manager.tunnel_manager:main`, which builds the server from the `scion_sdk.connector` entry point `tunnel_manager:connector` (`tunnel_manager/__init__.py:129`); the SDK `Connector` then lists the packaged skills, ontology and prompts. Shape: `pyproject.toml` entry point `tunnel-manager-mcp` plus the `connector = Connector(.)` object in `tunnel_manager/__init__.py`; the packaged `skills/`, `ontology/` and `prompts/` directories of `tunnel_manager` are reused as is, with no connector-local registration code. Proving test (planned): `tests/test_default_content_surfaces.py::test_default_content_surfaces`. Proving test (planned): `tests/test_default_content_surfaces.py::test_default_content_surfaces`. Proving test (planned): `tests/test_default_content_surfaces.py::test_default_content_surfaces`. Proving test (planned): `tests/test_default_content_surfaces.py::test_default_content_surfaces`. | `resources/list` includes `skill://` and `ontology://`; `prompts/list` includes each packaged prompt. |
