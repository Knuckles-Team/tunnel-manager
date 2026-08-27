#!/usr/bin/env python


import argparse
import concurrent.futures
import logging
import os
import secrets
import shlex
import sys
import tempfile
import time

import paramiko
import yaml
from agent_utilities.core.config import setting

from .connection_security import (
    ConnectionPolicyError,
    max_concurrency,
    max_fleet_hosts,
    max_output_bytes,
    max_transfer_bytes,
    quote_remote_path,
    validate_command,
    validate_host,
    validate_identity_path,
    validate_port,
    validate_public_key,
    validate_remote_path,
    validate_secret_ref,
    validate_timeout,
    validate_username,
    validated_known_hosts_path,
)
from .models import CommandResult, HostConfig
from .proxy_security import proxy_command_argv, proxy_command_string

__version__ = "3.1.0"


def _first_field(sources: tuple, keys: tuple, default=None):
    """Return the first truthy ``source.get(key)`` scanning sources outer, keys inner.

    Mirrors the ``a.get(k1) or a.get(k2) or b.get(k1) or b.get(k2) or default``
    fallback-chain idiom used throughout inventory-variable resolution: each
    source (e.g. host vars, then group vars, then top-level vars) is checked
    for every candidate key, in order, before moving to the next source.
    """

    for source in sources:
        for key in keys:
            value = source.get(key)
            if value:
                return value
    return default


def _password_ref(*sources: dict) -> str | None:
    """Read an inventory secret reference and reject legacy plaintext secrets."""

    for source in sources:
        if not isinstance(source, dict):
            continue
        if "ansible_ssh_pass" in source or "password" in source:
            raise ValueError(
                "plaintext inventory passwords are unsupported; configure password_ref"
            )
        value = source.get("ansible_ssh_pass_ref") or source.get("password_ref")
        if value:
            return validate_secret_ref(str(value))
    return None


def _known_hosts_file(*sources: dict) -> str | None:
    """Return the most-specific configured host-key trust store path."""

    for source in sources:
        if not isinstance(source, dict):
            continue
        value = source.get("ansible_ssh_known_hosts_file") or source.get(
            "known_hosts_file"
        )
        if value:
            return str(value)
    return None


def _load_execute_inventory_yaml(inventory: str, logger: logging.Logger) -> dict:
    """Load and parse the YAML inventory for ``Tunnel.execute_on_inventory``."""

    try:
        with open(inventory) as f:
            inventory_data = yaml.safe_load(f) or {}
        logger.debug("Loaded configured inventory data")
        return inventory_data
    except FileNotFoundError:
        logger.error("Configured inventory file was not found")
        print("Error: configured inventory file was not found", file=sys.stderr)
        raise
    except yaml.YAMLError as e:
        logger.error("Operation failed: error_type=%s", type(e).__name__)
        print(f"Operation failed: {type(e).__name__}", file=sys.stderr)
        raise


def _ansible_hosts_to_parse_all(all_hosts: dict, children: dict) -> dict:
    """``group="all"``: direct hosts from ``all`` plus every child's hosts."""

    hosts_to_parse: dict = {}
    for alias, hvars in all_hosts.items():
        hosts_to_parse[alias] = (hvars or {}, {})
    for child_data in children.values():
        if isinstance(child_data, dict):
            g_hosts = child_data.get("hosts", {}) or {}
            g_vars = child_data.get("vars", {}) or {}
            for alias, hvars in g_hosts.items():
                hosts_to_parse[alias] = (hvars or {}, g_vars)
    return hosts_to_parse


def _ansible_hosts_to_parse_named_child(children: dict, group: str) -> dict:
    """A ``group`` matching a named entry under ``children``."""

    hosts_to_parse: dict = {}
    child_data = children[group]
    if isinstance(child_data, dict):
        g_hosts = child_data.get("hosts", {}) or {}
        g_vars = child_data.get("vars", {}) or {}
        for alias, hvars in g_hosts.items():
            hosts_to_parse[alias] = (hvars or {}, g_vars)
    return hosts_to_parse


def _ansible_hosts_to_parse_legacy_top_level(inventory_data: dict, group: str) -> dict:
    """A ``group`` found as a legacy top-level key (outside ``children``)."""

    hosts_to_parse: dict = {}
    legacy_hosts = inventory_data[group]["hosts"] or {}
    legacy_vars = inventory_data[group].get("vars", {}) or {}
    for alias, hvars in legacy_hosts.items():
        hosts_to_parse[alias] = (hvars or {}, legacy_vars)
    return hosts_to_parse


def _ansible_hosts_to_parse(
    inventory_data: dict,
    group: str,
    all_hosts: dict,
    children: dict,
    logger: logging.Logger,
) -> dict:
    """Select the ``alias -> (host_vars, group_vars)`` set for ``group``.

    Tries, in order: the synthetic ``all`` group (direct hosts + every
    child's hosts), a named ``children`` entry, then a legacy top-level key
    outside ``children`` that itself carries a ``hosts`` mapping.
    """

    if group == "all":
        return _ansible_hosts_to_parse_all(all_hosts, children)

    if group in children:
        return _ansible_hosts_to_parse_named_child(children, group)

    # Group not found in children. Check if defined as a top-level key outside children
    if (
        group in inventory_data
        and isinstance(inventory_data[group], dict)
        and "hosts" in inventory_data[group]
    ):
        return _ansible_hosts_to_parse_legacy_top_level(inventory_data, group)

    logger.error("Configured inventory group was not found or is invalid")
    print("Error: configured inventory group is invalid", file=sys.stderr)
    raise ValueError("configured inventory group is invalid")


def _ansible_host_entry(alias: str, hvars: dict, g_vars: dict, all_vars: dict) -> dict:
    """Build one host entry from Ansible-style host/group/all variable layers."""

    sources = (hvars, g_vars, all_vars)
    username = _first_field(sources, ("ansible_user", "user"), "")
    key_path = _first_field(
        sources, ("key_path", "identity_file", "ansible_ssh_private_key_file")
    )
    port = _first_field(sources, ("ansible_port", "port"), 22)
    return {
        "hostname": _first_field((hvars,), ("ansible_host", "hostname"), alias),
        "username": username,
        "password_ref": _password_ref(hvars, g_vars, all_vars),
        "known_hosts_file": _known_hosts_file(hvars, g_vars, all_vars),
        "key_path": key_path,
        "port": int(port) if port else 22,
    }


def _hosts_from_ansible_style_inventory(
    inventory_data: dict, group: str, logger: logging.Logger
) -> list[dict]:
    """Resolve ``group`` hosts from an Ansible-style inventory (``all``/``children``)."""

    hosts: list[dict] = []
    all_group = inventory_data["all"]
    all_vars = all_group.get("vars", {}) or {}
    all_hosts = all_group.get("hosts", {}) or {}
    children = all_group.get("children", {}) or {}

    hosts_to_parse = _ansible_hosts_to_parse(
        inventory_data, group, all_hosts, children, logger
    )

    for alias, (hvars, g_vars) in hosts_to_parse.items():
        host_entry = _ansible_host_entry(alias, hvars, g_vars, all_vars)
        if not host_entry["username"]:
            logger.error("No username specified for configured host")
            print("Error: no username specified for configured host", file=sys.stderr)
            continue
        logger.debug("Added inventory host")
        hosts.append(host_entry)

    return hosts


def _legacy_flat_host_entry(alias: str, hvars: dict) -> dict:
    """Build one host entry for the legacy flat (``group="all"``) shape.

    NOTE: field precedence here (``port`` before ``ansible_port``,
    ``key_path`` before ``ansible_ssh_private_key_file``) intentionally
    matches the pre-existing behavior of this branch, which differs from
    ``_legacy_grouped_host_entry`` below -- see CXA-FL-TUNNELMANAGER-01
    bug report for the precedence-inconsistency finding.
    """

    key_path = _first_field(
        (hvars,), ("key_path", "identity_file", "ansible_ssh_private_key_file")
    )
    port = _first_field((hvars,), ("port", "ansible_port"), 22)
    return {
        "hostname": _first_field((hvars,), ("hostname", "ansible_host"), alias),
        "username": _first_field((hvars,), ("user", "username", "ansible_user"), ""),
        "password_ref": _password_ref(hvars),
        "known_hosts_file": _known_hosts_file(hvars),
        "key_path": key_path,
        "port": int(port) if port else 22,
    }


def _legacy_grouped_host_entry(host: str, hvars: dict) -> dict:
    """Build one host entry for the legacy group-as-top-level-key shape.

    NOTE: field precedence here (``ansible_port`` before ``port``,
    ``ansible_ssh_private_key_file`` before ``key_path``) intentionally
    matches the pre-existing behavior of this branch -- see
    ``_legacy_flat_host_entry`` above and the CXA-FL-TUNNELMANAGER-01 bug
    report for the precedence-inconsistency finding.
    """

    key_path = _first_field(
        (hvars,), ("ansible_ssh_private_key_file", "key_path", "identity_file")
    )
    port = _first_field((hvars,), ("ansible_port", "port"), 22)
    return {
        "hostname": _first_field((hvars,), ("ansible_host", "hostname"), host),
        "username": _first_field((hvars,), ("ansible_user", "user", "username")),
        "password_ref": _password_ref(hvars),
        "known_hosts_file": _known_hosts_file(hvars),
        "key_path": key_path,
        "port": int(port) if port else 22,
    }


def _legacy_flat_all_hosts(inventory_data: dict, logger: logging.Logger) -> list[dict]:
    """``group="all"``: treat every top-level dict entry as a host."""

    hosts: list[dict] = []
    for alias, hvars in inventory_data.items():
        if isinstance(hvars, dict):
            host_entry = _legacy_flat_host_entry(alias, hvars)
            if not host_entry["username"]:
                logger.error("No username specified for configured host")
                continue
            hosts.append(host_entry)
    return hosts


def _legacy_grouped_hosts(inventory_data: dict, group: str, logger: logging.Logger) -> list[dict]:
    """Legacy style with ``group`` as a top-level key containing a ``hosts`` mapping."""

    hosts: list[dict] = []
    for host, vars in inventory_data[group]["hosts"].items():
        host_entry = _legacy_grouped_host_entry(host, vars or {})
        if not host_entry["username"]:
            logger.error("No username specified for configured host")
            continue
        hosts.append(host_entry)
    return hosts


def _hosts_from_legacy_flat_inventory(
    inventory_data: dict, group: str, logger: logging.Logger
) -> list[dict]:
    """Resolve ``group`` hosts from a legacy non-Ansible flat/key-value inventory."""

    if group == "all":
        return _legacy_flat_all_hosts(inventory_data, logger)

    if (
        group in inventory_data
        and isinstance(inventory_data[group], dict)
        and "hosts" in inventory_data[group]
        and isinstance(inventory_data[group]["hosts"], dict)
    ):
        return _legacy_grouped_hosts(inventory_data, group, logger)

    logger.error("Configured inventory group was not found or is invalid")
    print("Error: configured inventory group is invalid", file=sys.stderr)
    raise ValueError("configured inventory group is invalid")


def _run_func_on_inventory_hosts(
    hosts: list[dict],
    func,
    parallel: bool,
    max_threads: int,
    logger: logging.Logger,
) -> None:
    """Sequentially or concurrently invoke ``func(host)`` for every resolved host."""

    if parallel:
        if isinstance(max_threads, bool):
            raise ConnectionPolicyError("Invalid fleet concurrency")
        max_threads = max(1, min(int(max_threads), max_concurrency(), len(hosts)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(func, host) for host in hosts]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error("Operation failed: error_type=%s", type(e).__name__)
                    print(f"Operation failed: {type(e).__name__}", file=sys.stderr)
    else:
        for host in hosts:
            func(host)


def _atomic_private_yaml(path: str, value: object) -> None:
    """Write inventory data atomically with owner-only permissions."""

    directory = os.path.dirname(path) or "."
    directory_preexisted = os.path.isdir(directory)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if not directory_preexisted:
        # Only harden a directory this call created itself. A pre-existing
        # directory (e.g. a shared parent the caller chose, or a tempdir in
        # tests) may not be owned by this process — forcing 0o700 on it can
        # raise PermissionError, or worse, unintentionally lock out other
        # legitimate users of a shared path. The inventory FILE below is
        # always hardened to 0o600 regardless, which is what actually
        # protects the persisted secret references.
        os.chmod(directory, 0o700)
    descriptor, temp_path = tempfile.mkstemp(prefix=".inventory.", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        payload = yaml.safe_dump(value, default_flow_style=False).encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def default_inventory_path() -> str:
    """Resolve the shared inventory path.

    The inventory is shared across the ecosystem (the HostManager library, the
    tunnel-manager CLI/MCP server, container-manager-mcp, and the ssh-bootstrap
    skill all read the same file). The standard filename is now ``inventory.yml``,
    but earlier builds wrote ``inventory.yaml``; this resolver keeps both working:

    1. ``$XDG_CONFIG_HOME/agent-utilities/inventory.yml`` if it exists, else
    2. ``$XDG_CONFIG_HOME/agent-utilities/inventory.yaml`` if it exists (legacy), else
    3. ``inventory.yml`` (the new standard for a fresh install).

    ``XDG_CONFIG_HOME`` defaults to ``~/.config``.
    """
    xdg_config = setting("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    config_dir = os.path.join(xdg_config, "agent-utilities")
    yml = os.path.join(config_dir, "inventory.yml")
    yaml_legacy = os.path.join(config_dir, "inventory.yaml")
    if os.path.exists(yml):
        return yml
    if os.path.exists(yaml_legacy):
        return yaml_legacy
    return yml


class HostManager:
    def __init__(self, config_file: str = None):
        if config_file:
            self.config_file = config_file
        else:
            self.config_file = default_inventory_path()

        self.logger = logging.getLogger(__name__)
        self.hosts = {}
        self._inventory_load_failed = False
        self.load_inventory()

    def load_inventory(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    raw = yaml.safe_load(f) or {}

                # Check if it's an Ansible-style inventory
                if "all" in raw and isinstance(raw["all"], dict):
                    flattened = {}
                    all_group = raw["all"]
                    children = all_group.get("children", {})
                    all_hosts = all_group.get("hosts", {}) or {}
                    all_vars = all_group.get("vars", {}) or {}

                    # Parse hosts at 'all' level
                    for alias, hvars in all_hosts.items():
                        if not hvars:
                            hvars = {}
                        entry = {
                            "hostname": hvars.get("ansible_host", alias),
                            "user": hvars.get("ansible_user")
                            or all_vars.get("ansible_user", ""),
                            "password_ref": _password_ref(hvars, all_vars),
                            "known_hosts_file": _known_hosts_file(hvars, all_vars),
                            "port": int(
                                hvars.get("ansible_port")
                                or all_vars.get("ansible_port")
                                or 22
                            ),
                            "identity_file": hvars.get("ansible_ssh_private_key_file")
                            or all_vars.get("ansible_ssh_private_key_file"),
                            "proxy_command": hvars.get("ansible_ssh_common_args")
                            or all_vars.get("ansible_ssh_common_args"),
                            "key_path": hvars.get("key_path")
                            or all_vars.get("key_path")
                            or hvars.get("ansible_ssh_private_key_file")
                            or all_vars.get("ansible_ssh_private_key_file"),
                        }
                        flattened[alias] = entry

                    # Parse children groups
                    for group_data in children.values():
                        if not isinstance(group_data, dict):
                            continue
                        g_hosts = group_data.get("hosts", {}) or {}
                        g_vars = group_data.get("vars", {}) or {}

                        for alias, hvars in g_hosts.items():
                            if not hvars:
                                hvars = {}

                            user = (
                                hvars.get("ansible_user")
                                or g_vars.get("ansible_user")
                                or all_vars.get("ansible_user", "")
                            )
                            password_ref = _password_ref(hvars, g_vars, all_vars)
                            port = (
                                hvars.get("ansible_port")
                                or g_vars.get("ansible_port")
                                or all_vars.get("ansible_port", 22)
                            )
                            identity_file = (
                                hvars.get("ansible_ssh_private_key_file")
                                or g_vars.get("ansible_ssh_private_key_file")
                                or all_vars.get("ansible_ssh_private_key_file")
                            )
                            proxy_command = (
                                hvars.get("ansible_ssh_common_args")
                                or g_vars.get("ansible_ssh_common_args")
                                or all_vars.get("ansible_ssh_common_args")
                            )
                            key_path = (
                                hvars.get("key_path")
                                or g_vars.get("key_path")
                                or hvars.get("ansible_ssh_private_key_file")
                                or g_vars.get("ansible_ssh_private_key_file")
                            )

                            entry = {
                                "hostname": hvars.get("ansible_host", alias),
                                "user": user,
                                "password_ref": password_ref,
                                "known_hosts_file": _known_hosts_file(
                                    hvars, g_vars, all_vars
                                ),
                                "port": int(port) if port else 22,
                                "identity_file": identity_file,
                                "proxy_command": proxy_command,
                                "key_path": key_path,
                            }
                            flattened[alias] = entry
                    self.hosts = flattened
                else:
                    for entry in raw.values():
                        if isinstance(entry, dict):
                            password_ref = _password_ref(entry)
                            if password_ref:
                                entry["password_ref"] = password_ref
                            else:
                                entry.pop("password_ref", None)
                            entry.pop("password", None)
                            entry.pop("ansible_ssh_pass", None)
                    self.hosts = raw
                self._inventory_load_failed = False
                self.logger.info("Loaded configured inventory")
            except Exception:
                self.logger.error("Failed to load inventory")
                self.hosts = {}
                self._inventory_load_failed = True
        else:
            self.logger.info("No configured inventory found; starting empty")
            self.hosts = {}
            self._inventory_load_failed = False

    def save_inventory(self):
        try:
            if self._inventory_load_failed:
                raise RuntimeError(
                    "refusing to overwrite an inventory that could not be loaded"
                )
            os.makedirs(os.path.dirname(self.config_file) or ".", exist_ok=True)
            if self.config_file.endswith("inventory.yaml") or self.config_file.endswith(
                "inventory.yml"
            ):
                existing_raw = {}
                if os.path.exists(self.config_file):
                    try:
                        with open(self.config_file) as f:
                            existing_raw = yaml.safe_load(f) or {}
                    except Exception as exc:
                        raise RuntimeError(
                            "refusing to overwrite an unreadable inventory"
                        ) from exc

                if "all" not in existing_raw:
                    existing_raw = {
                        "all": {"children": {"managed": {"hosts": {}, "vars": {}}}}
                    }

                group_name = "managed"
                children = existing_raw["all"].setdefault("children", {})
                group_data = children.setdefault(group_name, {"hosts": {}, "vars": {}})
                g_hosts = group_data.setdefault("hosts", {})
                g_vars = group_data.setdefault("vars", {})

                for alias, entry in self.hosts.items():
                    if isinstance(entry, dict):
                        hostname = entry.get("hostname", alias)
                        user = entry.get("user")
                        password_ref = entry.get("password_ref")
                        if "password" in entry or "ansible_ssh_pass" in entry:
                            raise ValueError(
                                "plaintext inventory passwords are unsupported; configure password_ref"
                            )
                        port = entry.get("port", 22)
                        identity_file = entry.get("identity_file") or entry.get(
                            "key_path"
                        )
                        known_hosts_file = entry.get("known_hosts_file")

                        host_vars = g_hosts.setdefault(alias, {})
                        if not isinstance(host_vars, dict):
                            host_vars = {}
                            g_hosts[alias] = host_vars

                        host_vars["ansible_host"] = hostname
                        if user and user != g_vars.get("ansible_user"):
                            host_vars["ansible_user"] = user
                        host_vars.pop("ansible_ssh_pass", None)
                        host_vars.pop("password", None)
                        if password_ref:
                            host_vars["ansible_ssh_pass_ref"] = password_ref
                        else:
                            host_vars.pop("ansible_ssh_pass_ref", None)
                            host_vars.pop("password_ref", None)
                        if port and port != g_vars.get("ansible_port", 22):
                            host_vars["ansible_port"] = port
                        if identity_file and identity_file != g_vars.get(
                            "ansible_ssh_private_key_file"
                        ):
                            host_vars["ansible_ssh_private_key_file"] = identity_file
                        if known_hosts_file and known_hosts_file != g_vars.get(
                            "ansible_ssh_known_hosts_file"
                        ):
                            host_vars["ansible_ssh_known_hosts_file"] = known_hosts_file

                # Prune hosts the manager no longer knows about so remove_host()
                # actually deletes them from the file (the merge above only adds /
                # updates). load_inventory() flattens every group into self.hosts,
                # so any alias absent from self.hosts was deliberately removed.
                for alias in list(g_hosts.keys()):
                    if alias not in self.hosts:
                        del g_hosts[alias]

                _atomic_private_yaml(self.config_file, existing_raw)
            else:
                clean_hosts = {}
                for alias, entry in self.hosts.items():
                    clean = dict(entry)
                    if "password" in clean or "ansible_ssh_pass" in clean:
                        raise ValueError(
                            "plaintext inventory passwords are unsupported; configure password_ref"
                        )
                    clean_hosts[alias] = clean
                _atomic_private_yaml(self.config_file, clean_hosts)
            self.logger.info("Saved configured inventory")
        except Exception:
            self.logger.error("Failed to save inventory")
            raise RuntimeError("failed to save configured inventory") from None

    def add_host(
        self,
        alias: str,
        hostname: str,
        user: str,
        port: int = 22,
        identity_file: str = None,
        password: str = None,
        password_ref: str = None,
        known_hosts_file: str = None,
        proxy_command: str = None,
        **kwargs,
    ):
        if proxy_command:
            proxy_command_argv(
                proxy_command,
                hostname=hostname,
                port=port,
                username=user,
            )
        if password is not None:
            raise ValueError(
                "plaintext passwords cannot be persisted; configure password_ref"
            )
        host_config = HostConfig(
            hostname=hostname,
            user=user,
            port=port,
            identity_file=identity_file,
            password_ref=password_ref,
            known_hosts_file=known_hosts_file,
            proxy_command=proxy_command,
            **kwargs,
        )
        self.hosts[alias] = host_config.model_dump(exclude_unset=True)
        self.save_inventory()
        self.logger.info("Added inventory host")

    def remove_host(self, alias: str):
        if alias in self.hosts:
            del self.hosts[alias]
            self.save_inventory()
            self.logger.info("Removed inventory host")
        else:
            self.logger.warning("Inventory host was not found")

    def _entitled(self, namespace: str, names: list[str]) -> list[str]:
        """Filter a resource-name list to what the calling identity may reach.

        Routes the names through agent-utilities' shared identity-scoped resolver
        (CONCEPT:AU-OS.identity.identity-scoped-resource-autoload): a caller's
        Okta/Keycloak groups decide which SSH host aliases auto-load for them.
        The ambient ``SYSTEM_ACTOR`` (unauthenticated/local) holds ``admin`` →
        sees all, so behaviour is unchanged until a real identity scopes it
        down. Degrades to the full list if agent-utilities predates the
        resolver.
        """
        try:
            from agent_utilities.security.entitlements import (
                identity_scoped_resources,
            )
        except Exception:
            return list(names)
        return list(identity_scoped_resources(namespace, names))

    def list_hosts(self) -> dict[str, dict]:
        """List the host aliases the CALLER is entitled to, secrets redacted.

        Scoped to the caller's Okta/Keycloak identity
        (CONCEPT:AU-OS.identity.identity-scoped-resource-autoload); an
        unauthenticated/local caller (SYSTEM_ACTOR) sees all — unchanged from
        today. Each entry excludes ``password``/``password_ref`` in favor of a
        ``password_configured`` boolean so listing hosts never leaks secrets.
        """
        entitled = self._entitled("ssh", list(self.hosts.keys()))
        result = {}
        for alias in entitled:
            config = HostConfig(**self.hosts[alias])
            public = config.model_dump(exclude={"password", "password_ref"})
            public["password_configured"] = bool(config.password_ref)
            result[alias] = public
        return result

    def get_host(self, alias: str) -> HostConfig | None:
        """Get a host config by alias, denying an alias the caller isn't entitled to.

        Returns ``None`` when the alias is simply unknown (unchanged, callers
        fall back to raw connection params), but raises ``PermissionError``
        when the alias exists and the caller's identity is not entitled to it.
        """
        data = self.hosts.get(alias)
        if data is None:
            return None
        if alias not in self._entitled("ssh", [alias]):
            raise PermissionError(
                f"Your identity is not entitled to the ssh host '{alias}'."
            )
        return HostConfig(**data)


class Tunnel:
    def __init__(
        self,
        config: HostConfig = None,
        remote_host: str = None,
        username: str = None,
        password: str = None,
        port: int = 22,
        identity_file: str = None,
        certificate_file: str = None,
        proxy_command: str = None,
        known_hosts_file: str = None,
        ssh_config_file: str = os.path.expanduser("~/.ssh/config"),
        connect_timeout: int = 10,
        banner_timeout: int = 10,
        auth_timeout: int = 15,
        keepalive_interval: int = 30,
        connect_retries: int = 2,
        retry_backoff: float = 1.0,
    ):
        """
        Initialize the Tunnel class using either a Pydantic HostConfig model or legacy kwargs.

        :param config: HostConfig object containing connection details.
        :param ssh_config_file: Optional path to a custom SSH config file (defaults to ~/.ssh/config).
        """
        if config:
            self.remote_host = config.hostname
            self.username = config.user
            self.password = config.resolved_password()
            self.port = config.port
            self.identity_file = config.identity_file or config.key_path
            self.proxy_command = config.proxy_command
            self.certificate_file = config.extra_config.get("certificate_file")
            self.known_hosts_file = config.known_hosts_file
        else:
            self.remote_host = remote_host
            self.username = username
            self.password = password
            self.port = port
            self.identity_file = identity_file
            self.proxy_command = proxy_command
            self.certificate_file = certificate_file
            self.known_hosts_file = known_hosts_file

        self.known_hosts_file = self.known_hosts_file or setting("TUNNEL_KNOWN_HOSTS")

        self.remote_host = validate_host(self.remote_host)
        self.port = validate_port(self.port)

        self.ssh_client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)

        # Connection hardening tunables (stability fixes for flaky SSH).
        # Bounded timeouts prevent indefinite hangs; a small retry/backoff
        # absorbs transient auth/banner failures on otherwise-reachable hosts.
        self.connect_timeout = validate_timeout(
            connect_timeout, default=10, maximum=300
        )
        self.banner_timeout = validate_timeout(banner_timeout, default=10, maximum=300)
        self.auth_timeout = validate_timeout(auth_timeout, default=15, maximum=300)
        self.keepalive_interval = validate_timeout(
            keepalive_interval, default=30, maximum=300
        )
        if isinstance(connect_retries, bool) or not 1 <= int(connect_retries) <= 5:
            raise ConnectionPolicyError("Invalid SSH retry configuration")
        self.connect_retries = int(connect_retries)
        if not isinstance(retry_backoff, (int, float)) or not 0 <= retry_backoff <= 10:
            raise ConnectionPolicyError("Invalid SSH retry configuration")
        self.retry_backoff = float(retry_backoff)

        self.ssh_config = paramiko.SSHConfig()
        if os.path.exists(ssh_config_file) and os.path.isfile(ssh_config_file):
            with open(ssh_config_file) as f:
                self.ssh_config.parse(f)
            self.logger.info("Loaded configured SSH client settings")
        else:
            self.logger.warning("Configured SSH client settings were not found")

        host_config_ssh = self.ssh_config.lookup(self.remote_host) or {}

        self.username = self.username or host_config_ssh.get("user")
        self.identity_file = self.identity_file or (
            host_config_ssh.get("identityfile")[0]
            if host_config_ssh.get("identityfile")
            else None
        )
        self.certificate_file = self.certificate_file or host_config_ssh.get(
            "certificatefile"
        )
        self.proxy_command = self.proxy_command or host_config_ssh.get("proxycommand")

        if not self.username:
            raise ValueError("Username must be provided via parameter or SSH config.")
        self.username = validate_username(self.username)
        if not self.identity_file and not self.password:
            self.logger.info(
                "Neither identity_file nor password was explicitly provided. "
                "Will attempt authentication using local SSH Agent and default keys."
            )

    def connect(self, timeout=None):
        if (
            self.ssh_client
            and self.ssh_client.get_transport()
            and self.ssh_client.get_transport().is_active()
        ):
            return

        connect_timeout = validate_timeout(
            timeout, default=self.connect_timeout, maximum=300
        )

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.load_system_host_keys()
        if self.known_hosts_file:
            self.ssh_client.load_host_keys(
                validated_known_hosts_path(self.known_hosts_file)
            )
        self.ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())

        # 1. Path Expansion & Normalization (Linux & Windows)
        expanded_identity = None
        if self.identity_file:
            expanded_identity = validate_identity_path(self.identity_file)
            self.logger.info("Resolved configured SSH identity")

        expanded_cert = None
        if self.certificate_file:
            expanded_cert = os.path.abspath(os.path.expanduser(self.certificate_file))
            self.logger.info("Resolved configured SSH certificate")

        # 2. Proxy Command Token Expansion & Platform Resolution (Linux & Windows)
        proxy = None
        if self.proxy_command:
            proxy_argv = proxy_command_argv(
                self.proxy_command,
                hostname=self.remote_host,
                port=self.port,
                username=self.username or "",
            )
            proxy = paramiko.ProxyCommand(proxy_command_string(proxy_argv))
            self.logger.info("Using an allowlisted SSH proxy executable")

        private_key = None
        if expanded_identity:
            try:
                private_key = paramiko.Ed25519Key.from_private_key_file(
                    expanded_identity
                )
                self.logger.info("Loaded configured ED25519 identity")
            except paramiko.ssh_exception.SSHException:
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(
                        expanded_identity
                    )
                    self.logger.info("Loaded configured RSA identity")
                except (OSError, paramiko.ssh_exception.SSHException) as exc:
                    raise ConnectionPolicyError(
                        "Configured SSH identity could not be loaded"
                    ) from exc

            if expanded_cert:
                private_key.load_certificate(expanded_cert)
                self.logger.info("Loaded configured SSH certificate")

        # 3. Connection with bounded timeouts + retry/backoff. SSH Agent and
        # default key discovery stay enabled for zero-burden RSA fallback.
        last_exc = None
        for attempt in range(1, self.connect_retries + 1):
            try:
                self.ssh_client.connect(
                    self.remote_host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    pkey=private_key,
                    sock=proxy,
                    timeout=connect_timeout,
                    banner_timeout=self.banner_timeout,
                    auth_timeout=self.auth_timeout,
                    look_for_keys=True,
                    allow_agent=True,
                )
                transport = self.ssh_client.get_transport()
                if transport is not None:
                    # Detect silently-dropped idle connections.
                    transport.set_keepalive(self.keepalive_interval)
                self.logger.info("SSH connection established: attempt=%d", attempt)
                return
            except Exception as e:
                last_exc = e
                self.logger.warning(
                    "SSH connection failed: attempt=%d max_attempts=%d error_type=%s",
                    attempt,
                    self.connect_retries,
                    type(e).__name__,
                )
                if attempt < self.connect_retries:
                    time.sleep(self.retry_backoff * attempt)

        self.logger.error(
            "SSH connection failed after retries: attempts=%d error_type=%s",
            self.connect_retries,
            type(last_exc).__name__,
        )
        raise ConnectionError("SSH connection failed") from None

    def run_command(
        self, command, timeout=None, *, propagate_errors: bool = False
    ) -> CommandResult:
        """
        Run a shell command on the remote host.

        :param command: The command to execute.
        :param timeout: Optional command execution timeout in seconds.
        :param propagate_errors: Re-raise typed timeout/policy failures for a
            structured caller. The default preserves the legacy result shape.
        :return: CommandResult object.
        """
        command = validate_command(command)
        command_timeout = validate_timeout(
            timeout, default=60, maximum=86_400 if propagate_errors else 3_600
        )
        self.connect()
        try:
            _stdin, stdout, stderr = self.ssh_client.exec_command(
                command, timeout=command_timeout
            )  # nosec B601
            channel = stdout.channel
            channel.settimeout(command_timeout)
            output_limit = max_output_bytes()
            if isinstance(channel, paramiko.Channel):
                out_buffer = bytearray()
                err_buffer = bytearray()
                deadline = time.monotonic() + command_timeout
                while True:
                    while channel.recv_ready():
                        remaining = output_limit - len(out_buffer) - len(err_buffer)
                        chunk = channel.recv(min(65_536, max(1, remaining + 1)))
                        out_buffer.extend(chunk)
                        if len(out_buffer) + len(err_buffer) > output_limit:
                            channel.close()
                            raise ConnectionPolicyError(
                                "Managed command output limit exceeded"
                            )
                    while channel.recv_stderr_ready():
                        remaining = output_limit - len(out_buffer) - len(err_buffer)
                        chunk = channel.recv_stderr(min(65_536, max(1, remaining + 1)))
                        err_buffer.extend(chunk)
                        if len(out_buffer) + len(err_buffer) > output_limit:
                            channel.close()
                            raise ConnectionPolicyError(
                                "Managed command output limit exceeded"
                            )
                    if (
                        channel.exit_status_ready()
                        and not channel.recv_ready()
                        and not channel.recv_stderr_ready()
                    ):
                        break
                    if time.monotonic() >= deadline:
                        channel.close()
                        raise TimeoutError("Managed command timed out")
                    time.sleep(0.01)
            else:
                # Test/fake-client compatibility path. Real Paramiko transports
                # always expose ``paramiko.Channel`` and use the concurrent drain
                # above, which prevents stdout/stderr pipe deadlocks.
                out_buffer = bytearray(stdout.read(output_limit + 1))
                remaining = max(1, output_limit - len(out_buffer) + 1)
                err_buffer = bytearray(stderr.read(remaining))
                if len(out_buffer) + len(err_buffer) > output_limit:
                    raise ConnectionPolicyError("Managed command output limit exceeded")
            out = out_buffer.decode("utf-8", errors="replace").strip()
            err = err_buffer.decode("utf-8", errors="replace").strip()
            exit_status = channel.recv_exit_status()
            self.logger.info(
                "Managed command completed: success=%s stdout_chars=%d stderr_chars=%d",
                exit_status == 0,
                len(out),
                len(err),
            )
            return CommandResult(success=(exit_status == 0), stdout=out, stderr=err)
        except Exception as e:
            self.logger.error("Operation failed: error_type=%s", type(e).__name__)
            if propagate_errors and isinstance(
                e, (TimeoutError, ConnectionPolicyError)
            ):
                raise
            return CommandResult(
                success=False,
                error_message="ManagedCommandError",
                stderr="ManagedCommandError",
            )

    def send_file(self, local_path, remote_path):
        """
        Send (upload) a file to the remote host.
        :param local_path: Path to the local file.
        :param remote_path: Path on the remote host.
        """
        try:
            local_path = os.path.abspath(os.path.expanduser(local_path))
            remote_path = validate_remote_path(remote_path)

            self.logger.debug("Preparing managed SFTP upload")

            if not os.path.exists(local_path):
                err_msg = "Configured local file does not exist"
                self.logger.error("Configured local file does not exist")
                raise OSError(err_msg)
            if os.path.islink(local_path) or not os.path.isfile(local_path):
                err_msg = "Configured local path is not a regular file"
                self.logger.error("Configured local path is not a regular file")
                raise OSError(err_msg)
            if not os.access(local_path, os.R_OK):
                err_msg = "Configured local file is not readable"
                self.logger.error("Configured local file is not readable")
                raise PermissionError(err_msg)
            file_size = os.path.getsize(local_path)
            if file_size > max_transfer_bytes():
                raise ConnectionPolicyError("Managed file transfer limit exceeded")

            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(local_path, flags)
            except OSError as open_err:
                err_msg = "Failed to open configured local file"
                self.logger.error(
                    "Failed to open configured local file: error_type=%s",
                    type(open_err).__name__,
                )
                raise OSError(err_msg) from open_err

            self.connect()
            if not self.sftp:
                self.sftp = self.ssh_client.open_sftp()
                self.sftp.get_channel().settimeout(self.connect_timeout)
            self.logger.debug("Opening managed SFTP upload")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                self.sftp.putfo(stream, remote_path, file_size=file_size, confirm=True)
            self.logger.info("Managed SFTP upload completed")
        except Exception as e:
            self.logger.error("Operation failed: error_type=%s", type(e).__name__)
            raise
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
            if self.sftp:
                self.sftp.close()
                self.sftp = None

    def receive_file(self, remote_path, local_path):
        """
        Receive (download) a file from the remote host.

        :param remote_path: Path on the remote host.
        :param local_path: Path to save the local file.
        """
        try:
            remote_path = validate_remote_path(remote_path)
            local_path = os.path.abspath(os.path.expanduser(local_path))
            if os.path.lexists(local_path) and os.path.islink(local_path):
                raise ConnectionPolicyError("Managed download destination is unsafe")
            self.connect()
            if not self.sftp:
                self.sftp = self.ssh_client.open_sftp()
                self.sftp.get_channel().settimeout(self.connect_timeout)
            remote_info = self.sftp.stat(remote_path)
            if remote_info.st_size > max_transfer_bytes():
                raise ConnectionPolicyError("Managed file transfer limit exceeded")
            destination_dir = os.path.dirname(local_path) or "."
            descriptor, temp_path = tempfile.mkstemp(
                prefix=".managed-download.", dir=destination_dir
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                self.sftp.getfo(remote_path, stream)
            os.replace(temp_path, local_path)
            temp_path = ""
            os.chmod(local_path, 0o600)
            self.logger.info("SFTP file transfer completed")
        except Exception as e:
            self.logger.error(
                "SFTP file transfer failed: error_type=%s", type(e).__name__
            )
            raise
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
            if "temp_path" in locals() and temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
            if self.sftp:
                self.sftp.close()
                self.sftp = None

    def check_ssh_server(self):
        """
        Check if the SSH server is running and configured for key-based auth on the remote host.
        :return: Tuple (bool, str) indicating if SSH server is running and any error message.
        """
        try:
            self.connect()
            out, err = self.run_command(
                "systemctl status sshd || ps aux | grep '[s]shd'"
            )
            if "running" in out.lower() or "sshd" in out.lower():
                out, err = self.run_command(
                    "grep '^PubkeyAuthentication' /etc/ssh/sshd_config"
                )
                if "PubkeyAuthentication yes" in out:
                    return True, "SSH server running with key-based auth enabled."
                return False, "SSH server running but key-based auth not enabled."
            return False, "SSH server not running."
        except Exception as e:
            self.logger.error(
                "Failed to check SSH server: error_type=%s", type(e).__name__
            )
            return False, f"Failed to check SSH server: {type(e).__name__}"
        finally:
            self.close()

    def test_key_auth(self, local_key_path):
        """
        Test if key-based authentication works for the remote host.
        :param local_key_path: Path to the private key to test.
        :return: Tuple (bool, str) indicating success and any error message.
        """
        local_key_path = os.path.expanduser(local_key_path)
        try:
            temp_tunnel = Tunnel(
                config=HostConfig(
                    hostname=self.remote_host,
                    user=self.username,
                    key_path=local_key_path,
                    known_hosts_file=self.known_hosts_file,
                )
            )
            temp_tunnel.connect()
            temp_tunnel.close()
            return True, "Key-based authentication successful."
        except Exception as e:
            self.logger.error(
                "Key authentication test failed: error_type=%s", type(e).__name__
            )
            return False, f"Key auth test failed: {type(e).__name__}"

    def close(self):
        """
        Close the SSH connection.
        """
        if self.ssh_client:
            self.ssh_client.close()
            self.logger.info("SSH connection closed")
            self.ssh_client = None

    def setup_passwordless_ssh(
        self, local_key_path=os.path.expanduser("~/.ssh/id_rsa"), key_type="ed25519"
    ):
        """
        Set up passwordless SSH by copying a public key to the remote host.
        Requires password-based authentication to be configured.

        :param local_key_path: Path to the local private key (public key is assumed to be .pub).
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        """
        if not self.password:
            raise ValueError("Password-based authentication required for setup.")

        local_key_path = os.path.expanduser(local_key_path)
        pub_key_path = local_key_path + ".pub"

        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(pub_key_path):
            import subprocess

            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        local_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "ed25519",
                        "-f",
                        local_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            self.logger.info("Generated managed SSH key pair: key_type=%s", key_type)

        with open(pub_key_path) as f:
            pub_key = validate_public_key(f.read())

        try:
            self.connect()
            self.run_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
            self.run_command(
                f"printf '%s\\n' {shlex.quote(pub_key)} >> ~/.ssh/authorized_keys"
            )
            self.run_command("chmod 600 ~/.ssh/authorized_keys")
            self.logger.info("Configured managed SSH key authentication")
        except Exception as e:
            self.logger.error(
                "Failed to set up passwordless SSH: error_type=%s",
                type(e).__name__,
            )
            raise
        finally:
            self.close()

    @staticmethod
    def execute_on_inventory(
        inventory, func, group="all", parallel=False, max_threads=5
    ):
        """
        Execute a function on all hosts in the specified group of the YAML inventory, sequentially or in parallel.
        :param inventory: Path to the YAML inventory file.
        :param func: Function to execute, takes host dict as argument.
        :param group: Inventory group to target (default: 'all').
        :param parallel: Whether to run in parallel using threads.
        :param max_threads: Maximum number of threads if parallel.
        """
        logger = logging.getLogger("Tunnel")
        logger.info("Processing configured inventory group")
        print("Loading configured inventory group...", file=sys.stderr)

        inventory_data = _load_execute_inventory_yaml(inventory, logger)

        # Check if it's an Ansible-style inventory
        if "all" in inventory_data and isinstance(inventory_data["all"], dict):
            hosts = _hosts_from_ansible_style_inventory(inventory_data, group, logger)
        else:
            hosts = _hosts_from_legacy_flat_inventory(inventory_data, group, logger)

        if len(hosts) > max_fleet_hosts():
            raise ConnectionPolicyError("Configured inventory exceeds the fleet limit")
        logger.info("Found inventory hosts: host_count=%d", len(hosts))
        print(f"Found {len(hosts)} inventory hosts", file=sys.stderr)

        if not hosts:
            logger.warning("No valid hosts found in configured inventory group")
            print("Warning: no valid inventory hosts found", file=sys.stderr)
            return

        _run_func_on_inventory_hosts(hosts, func, parallel, max_threads, logger)
        print("Completed inventory-group processing", file=sys.stderr)

    def remove_host_key(
        self, known_hosts_path=os.path.expanduser("~/.ssh/known_hosts")
    ) -> str:
        """
        Remove the host key for the remote host from the known_hosts file.
        :param known_hosts_path: Path to the known_hosts file (default: ~/.ssh/known_hosts).
        """
        known_hosts_path = validated_known_hosts_path(known_hosts_path)
        kh = paramiko.HostKeys()
        kh.load(known_hosts_path)
        if self.remote_host in kh:
            del kh[self.remote_host]
            kh.save(known_hosts_path)
            os.chmod(known_hosts_path, 0o600)
            self.logger.info("Removed managed-host key")
            return "Removed managed-host key"
        else:
            self.logger.warning("Managed-host key was not found")
            return "Managed-host key was not found"

    def copy_ssh_config(
        self, local_config_path, remote_config_path=os.path.expanduser("~/.ssh/config")
    ):
        """
        Copy a local SSH config to the remote host’s ~/.ssh/config.
        :param local_config_path: Path to the local config file.
        :param remote_config_path: Path on remote (default ~/.ssh/config).
        """
        self.connect()
        self.run_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
        self.send_file(local_config_path, remote_config_path)
        result = self.run_command(
            f"chmod 600 -- {quote_remote_path(remote_config_path)}"
        )
        if not result.success:
            raise ConnectionError("Managed SSH configuration copy failed")
        self.logger.info("Copied managed SSH configuration")

    def rotate_ssh_key(self, new_key_path, key_type="ed25519"):
        """
        Rotate the SSH key by generating a new pair and updating authorized_keys.
        :param new_key_path: Path for the new private key.
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        """
        new_key_path = os.path.expanduser(new_key_path)
        new_pub_path = new_key_path + ".pub"
        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(new_key_path):
            import subprocess

            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        new_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "ed25519",
                        "-f",
                        new_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            self.logger.info("Generated new managed key pair: key_type=%s", key_type)

        with open(new_pub_path) as f:
            new_pub = validate_public_key(f.read())

        old_pub = None
        if self.identity_file:
            old_key_path = os.path.expanduser(self.identity_file)
            old_pub_path = old_key_path + ".pub"
            if os.path.exists(old_pub_path):
                with open(old_pub_path) as f:
                    old_pub = f.read().strip()

        self.connect()
        out, err = self.run_command("cat ~/.ssh/authorized_keys")
        auth_keys = out.splitlines()
        new_auth = [
            line
            for line in auth_keys
            if line.strip() and (old_pub is None or line.strip() != old_pub)
        ]
        new_auth.append(new_pub)

        new_auth_joined = "\n".join(new_auth)
        remote_temp = f"/tmp/.authorized_keys.{secrets.token_hex(16)}"  # nosec B108
        descriptor, local_temp = tempfile.mkstemp(prefix=".authorized_keys.")
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(new_auth_joined)
                stream.write("\n")
            self.send_file(local_temp, remote_temp)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if os.path.exists(local_temp):
                os.unlink(local_temp)
        move_result = self.run_command(
            f"mv -- {quote_remote_path(remote_temp)} ~/.ssh/authorized_keys"
        )
        if not move_result.success:
            self.run_command(f"rm -f -- {quote_remote_path(remote_temp)}")
            raise ConnectionError("Managed SSH key rotation failed")
        chmod_result = self.run_command("chmod 600 ~/.ssh/authorized_keys")
        if not chmod_result.success:
            raise ConnectionError("Managed SSH key rotation failed")

        self.identity_file = new_key_path
        self.password = None
        self.logger.info("Rotated managed SSH key: key_type=%s", key_type)
        logging.info("Managed SSH key rotation requires client configuration update")

    @staticmethod
    def setup_all_passwordless_ssh(
        inventory,
        shared_key_path=os.path.expanduser("~/.ssh/id_shared"),
        key_type="ed25519",
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Set up passwordless SSH for all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param shared_key_path: Path to a shared private key (optional, generates if missing).
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        """
        shared_key_path = os.path.expanduser(shared_key_path)
        shared_pub_key_path = shared_key_path + ".pub"
        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(shared_key_path):
            import subprocess

            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        shared_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "ed25519",
                        "-f",
                        shared_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            logging.info("Generated shared managed key pair: key_type=%s", key_type)

        with open(shared_pub_key_path) as f:
            shared_pub_key = validate_public_key(f.read())

        def setup_host(host):
            hostname = host["hostname"]
            username = host["username"]
            password_ref = host.get("password_ref")
            key_path = host.get("key_path", shared_key_path)

            logging.info("Setting up shared-key authentication for an inventory host")

            tunnel = Tunnel(
                config=HostConfig(
                    hostname=hostname,
                    user=username,
                    password_ref=password_ref,
                    known_hosts_file=host.get("known_hosts_file"),
                )
            )
            tunnel.setup_passwordless_ssh(local_key_path=key_path, key_type=key_type)

            try:
                tunnel.connect()
                tunnel.run_command(
                    f"printf '%s\\n' {shlex.quote(shared_pub_key)} >> ~/.ssh/authorized_keys"
                )
                tunnel.run_command("chmod 600 ~/.ssh/authorized_keys")
                logging.info(
                    "Shared inventory-host key installed: key_type=%s", key_type
                )
            except Exception as e:
                logging.error(
                    "Failed to install a shared inventory-host key: error_type=%s",
                    type(e).__name__,
                )
            finally:
                tunnel.close()

            result, msg = tunnel.test_key_auth(key_path)
            logging.info("Inventory-host key authentication tested: success=%s", result)

        Tunnel.execute_on_inventory(inventory, setup_host, group, parallel, max_threads)

    @staticmethod
    def setup_full_mesh_ssh(
        inventory,
        key_path=os.path.expanduser("~/.ssh/id_ed25519"),
        key_type="ed25519",
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Set up full-mesh passwordless SSH for all hosts in the specified group.
        Ensures every host can SSH to every other host, including the local machine,
        without password prompts. Supports POSIX and Windows remotes.
        """
        import subprocess

        logger = logging.getLogger("Tunnel")
        logger.info("Starting native full-mesh SSH bootstrap")

        # 1. Local key generation
        key_path = os.path.expanduser(key_path)
        pub_key_path = key_path + ".pub"
        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(key_path):
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.run(
                    ["/usr/bin/ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            logger.info("Generated local managed key pair: key_type=%s", key_type)

        with open(pub_key_path) as f:
            local_pub_key = validate_public_key(f.read())

        # 2. Parse inventory hosts
        try:
            with open(inventory) as f:
                inventory_data = yaml.safe_load(f)
        except Exception:
            logger.error("Failed to read inventory file")
            raise

        hosts = []
        if (
            group in inventory_data
            and isinstance(inventory_data[group], dict)
            and "hosts" in inventory_data[group]
            and isinstance(inventory_data[group]["hosts"], dict)
        ):
            for host_name, vars in inventory_data[group]["hosts"].items():
                host_entry = {
                    "name": host_name,
                    "hostname": vars.get("ansible_host", host_name),
                    "username": vars.get("ansible_user"),
                    "password_ref": _password_ref(vars),
                    "known_hosts_file": _known_hosts_file(vars),
                    "key_path": vars.get("ansible_ssh_private_key_file") or key_path,
                }
                if host_entry["username"]:
                    hosts.append(host_entry)
        else:
            raise ValueError("configured inventory group is invalid")

        if not hosts:
            logger.warning("No valid hosts found in configured inventory group")
            return {"status": "success", "host_results": [], "errors": []}

        # First pass - setup passwordless access, detect remote OS, ensure keygen and read pubkey
        host_results = {}

        def process_first_pass(host):
            hostname = host["hostname"]
            username = host["username"]
            password_ref = host.get("password_ref")
            kpath = host["key_path"]

            tunnel = Tunnel(
                config=HostConfig(
                    hostname=hostname,
                    user=username,
                    password_ref=password_ref,
                    identity_file=kpath,
                    known_hosts_file=host.get("known_hosts_file"),
                )
            )

            # Test key auth
            res, _ = tunnel.test_key_auth(kpath)
            if not res:
                if not password_ref:
                    raise ValueError(
                        "Key authentication failed without a credential reference"
                    )
                logger.info("Key authentication failed; attempting governed key setup")
                tunnel.setup_passwordless_ssh(local_key_path=kpath, key_type=key_type)

            # Re-connect to perform remote generation and detection
            tunnel.connect()
            try:
                # Detect OS
                is_windows = False
                res_os = tunnel.run_command("uname -s")
                if (
                    not res_os.success
                    or "uname" in res_os.stderr.lower()
                    or not res_os.stdout
                ):
                    is_windows = True

                # Check / generate key on remote
                if is_windows:
                    tunnel.run_command(
                        'if not exist "%USERPROFILE%\\.ssh" mkdir "%USERPROFILE%\\.ssh"'
                    )
                    gen_cmd = f'if not exist "%USERPROFILE%\\.ssh\\id_{key_type}" (ssh-keygen -t {key_type} -N "" -f "%USERPROFILE%\\.ssh\\id_{key_type}")'
                else:
                    tunnel.run_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
                    gen_cmd = f"if [ ! -f ~/.ssh/id_{key_type} ]; then ssh-keygen -t {key_type} -N '' -f ~/.ssh/id_{key_type}; fi"

                res_gen = tunnel.run_command(gen_cmd)
                if not res_gen.success:
                    raise RuntimeError(
                        f"Failed to generate key on remote host: {res_gen.stderr or res_gen.error_message}"
                    )

                # Read remote public key
                if is_windows:
                    read_cmd = f'type "%USERPROFILE%\\.ssh\\id_{key_type}.pub"'
                else:
                    read_cmd = f"cat ~/.ssh/id_{key_type}.pub"

                res_pub = tunnel.run_command(read_cmd)
                if not res_pub.success or not res_pub.stdout:
                    raise RuntimeError(
                        f"Failed to read public key from remote: {res_pub.stderr or res_pub.error_message}"
                    )
                remote_pub_key = validate_public_key(res_pub.stdout)

                # Extract local-perceived IP via SSH_CONNECTION
                if is_windows:
                    ip_cmd = "echo %SSH_CONNECTION%"
                else:
                    ip_cmd = "echo $SSH_CONNECTION"

                res_ip = tunnel.run_command(ip_cmd)
                client_ip = None
                if res_ip.success and res_ip.stdout:
                    parts = res_ip.stdout.strip().split()
                    if parts:
                        client_ip = parts[0]

                # Ensure local pub key is explicitly inside remote authorized_keys
                if is_windows:
                    tunnel.run_command(
                        f'echo {local_pub_key} >> "%USERPROFILE%\\.ssh\\authorized_keys"'
                    )
                else:
                    tunnel.run_command(
                        f"printf '%s\\n' {shlex.quote(local_pub_key)} >> "
                        "~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
                    )

                host_results[hostname] = {
                    "name": host["name"],
                    "hostname": hostname,
                    "username": username,
                    "key_path": kpath,
                    "is_windows": is_windows,
                    "remote_pub_key": remote_pub_key,
                    "client_ip": client_ip,
                    "status": "success",
                    "errors": [],
                }
            except Exception as e:
                host_results[hostname] = {
                    "name": host["name"],
                    "hostname": hostname,
                    "username": username,
                    "status": "failed",
                    "errors": [type(e).__name__],
                }
            finally:
                tunnel.close()

        # Run first pass (parallel or sequential)
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [executor.submit(process_first_pass, h) for h in hosts]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        logger.error("Error in first pass")
        else:
            for h in hosts:
                try:
                    process_first_pass(h)
                except Exception:
                    logger.error("Error in first pass")

        # Filter out failed hosts from second pass
        successful_hosts = [
            r for r in host_results.values() if r["status"] == "success"
        ]

        # Second pass distributes only authenticated public keys. Host-key trust
        # must be pre-provisioned through a governed known_hosts file; keyscan is
        # intentionally unsupported because it does not authenticate the key.
        def process_second_pass(host):
            hostname = host["hostname"]
            username = host["username"]
            kpath = host["key_path"]
            is_windows = host["is_windows"]

            tunnel = Tunnel(
                remote_host=hostname, username=username, identity_file=kpath
            )
            tunnel.connect()
            try:
                # Read existing authorized_keys
                if is_windows:
                    cat_cmd = 'type "%USERPROFILE%\\.ssh\\authorized_keys"'
                else:
                    cat_cmd = "cat ~/.ssh/authorized_keys"

                res_auth = tunnel.run_command(cat_cmd)
                existing_keys = res_auth.stdout if res_auth.success else ""

                # Collect and append keys
                keys_to_add = []
                if local_pub_key not in existing_keys:
                    keys_to_add.append(local_pub_key)

                for other_host in successful_hosts:
                    if other_host["hostname"] != hostname:
                        other_pub = other_host["remote_pub_key"]
                        if other_pub not in existing_keys:
                            keys_to_add.append(other_pub)

                if keys_to_add:
                    for key_to_add in keys_to_add:
                        if is_windows:
                            tunnel.run_command(
                                f'echo {key_to_add} >> "%USERPROFILE%\\.ssh\\authorized_keys"'
                            )
                        else:
                            tunnel.run_command(
                                f"printf '%s\\n' {shlex.quote(key_to_add)} >> "
                                "~/.ssh/authorized_keys"
                            )
                    if not is_windows:
                        tunnel.run_command("chmod 600 ~/.ssh/authorized_keys")

            except Exception as e:
                host_results[hostname]["status"] = "failed"
                host_results[hostname]["errors"].append(type(e).__name__)
            finally:
                tunnel.close()

        # Run second pass (parallel or sequential)
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [
                    executor.submit(process_second_pass, h) for h in successful_hosts
                ]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        logger.error("Error in second pass")
        else:
            for h in successful_hosts:
                try:
                    process_second_pass(h)
                except Exception:
                    logger.error("Error in second pass")

        # Local authorized_keys updates. known_hosts remains an independently
        # governed trust input and is never populated via unauthenticated scans.
        try:
            local_auth_path = os.path.expanduser("~/.ssh/authorized_keys")
            local_existing_keys = ""
            if os.path.exists(local_auth_path):
                with open(local_auth_path) as f:
                    local_existing_keys = f.read()

            with open(local_auth_path, "a") as f:
                for h in successful_hosts:
                    if h["remote_pub_key"] not in local_existing_keys:
                        f.write("\n" + h["remote_pub_key"] + "\n")

        except Exception:
            logger.error("Failed to update local authorized keys")

        # Assemble final result
        final_results = list(host_results.values())
        errors = []
        for r in final_results:
            errors.extend(r["errors"])

        return {
            "status": "success" if not errors else "failed",
            "host_results": final_results,
            "errors": errors,
            "known_hosts_preprovisioning_required": True,
        }

    @staticmethod
    def run_command_on_inventory(
        inventory, command, group="all", parallel=False, max_threads=5, timeout=None
    ):
        """
        Run a shell command on all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param command: The shell command to run.
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        :param timeout: Optional command execution timeout in seconds.
        """
        logger = logging.getLogger("Tunnel")
        logger.info("Running managed command on inventory group")
        print("Executing managed command on inventory group...", file=sys.stderr)

        def run_host(host):
            try:
                tunnel = Tunnel(
                    config=HostConfig(
                        hostname=host["hostname"],
                        user=host["username"],
                        password_ref=host.get("password_ref"),
                        key_path=host.get("key_path"),
                        known_hosts_file=host.get("known_hosts_file"),
                    )
                )
                tunnel.run_command(command, timeout=timeout)
                logger.info("Managed command completed on an inventory host")
                print("Managed command completed on an inventory host", file=sys.stderr)
                tunnel.close()
            except Exception as e:
                logger.error("Operation failed: error_type=%s", type(e).__name__)
                print(f"Operation failed: {type(e).__name__}", file=sys.stderr)

        try:
            Tunnel.execute_on_inventory(
                inventory, run_host, group, parallel, max_threads
            )
            print("Completed managed command execution", file=sys.stderr)
        except Exception as e:
            logger.error("Operation failed: error_type=%s", type(e).__name__)
            print(f"Managed command failed: {type(e).__name__}", file=sys.stderr)
            raise

    @staticmethod
    def copy_ssh_config_on_inventory(
        inventory,
        local_config_path,
        remote_config_path=os.path.expanduser("~/.ssh/config"),
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Copy local SSH config to all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param local_config_path: Local SSH config path.
        :param remote_config_path: Remote path (default ~/.ssh/config).
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        """

        def copy_host(host):
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password_ref=host.get("password_ref"),
                    key_path=host.get("key_path"),
                    known_hosts_file=host.get("known_hosts_file"),
                )
            )
            tunnel.copy_ssh_config(local_config_path, remote_config_path)
            tunnel.close()

        Tunnel.execute_on_inventory(inventory, copy_host, group, parallel, max_threads)

    @staticmethod
    def rotate_ssh_key_on_inventory(
        inventory,
        key_prefix=os.path.expanduser("~/.ssh/id_"),
        key_type="ed25519",
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Rotate SSH keys for all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param key_prefix: Prefix for new key paths (appends hostname).
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        """

        def rotate_host(host):
            new_key_path = os.path.expanduser(key_prefix + host["hostname"])
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password_ref=host.get("password_ref"),
                    key_path=host.get("key_path"),
                    known_hosts_file=host.get("known_hosts_file"),
                )
            )
            tunnel.rotate_ssh_key(new_key_path, key_type=key_type)
            logging.info("Rotated inventory-host SSH key: key_type=%s", key_type)
            tunnel.close()

        Tunnel.execute_on_inventory(
            inventory, rotate_host, group, parallel, max_threads
        )

    @staticmethod
    def send_file_on_inventory(
        inventory,
        local_path,
        remote_path,
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Upload a file to all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param local_path: Path to the local file to upload.
        :param remote_path: Path on the remote hosts to save the file.
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel execution.
        """

        def send_host(host):
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password_ref=host.get("password_ref"),
                    key_path=host.get("key_path"),
                    known_hosts_file=host.get("known_hosts_file"),
                )
            )
            tunnel.send_file(local_path, remote_path)
            logging.info("Inventory-host file upload completed")
            tunnel.close()

        if not os.path.exists(local_path):
            raise ValueError("Local upload source does not exist")

        Tunnel.execute_on_inventory(inventory, send_host, group, parallel, max_threads)

    @staticmethod
    def receive_file_on_inventory(
        inventory,
        remote_path: str,
        local_path_prefix,
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Download a file from all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param remote_path: Path on the remote hosts to download the file from.
        :param local_path_prefix: Local directory path prefix to save files (creates host-specific subdirectories).
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel execution.
        """

        def receive_host(host):
            host_dir = os.path.join(local_path_prefix, host["hostname"])
            os.makedirs(host_dir, exist_ok=True)
            local_path = os.path.join(f"{host_dir}", os.path.basename(remote_path))
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password_ref=host.get("password_ref"),
                    key_path=host.get("key_path"),
                    known_hosts_file=host.get("known_hosts_file"),
                )
            )
            tunnel.receive_file(remote_path, local_path)
            logging.info("Inventory-host file download completed")
            tunnel.close()

        os.makedirs(local_path_prefix, exist_ok=True)
        Tunnel.execute_on_inventory(
            inventory, receive_host, group, parallel, max_threads
        )


# A well-commented template documenting every supported host field and the
# Ansible-style group structure. Written verbatim by `tunnel-manager inventory init`.
INVENTORY_TEMPLATE = """\
# tunnel-manager / agent-utilities shared inventory
# ------------------------------------------------------------------------------
# Maps short host aliases (e.g. `edge-node`) to their SSH connection details. Every
# ecosystem surface reads THIS file: the HostManager Python API, the
# `tunnel-manager` CLI, the tunnel-manager-mcp MCP server, container-manager-mcp
# (cm_* host aliases), and the ssh-bootstrap skill. Define your fleet once here.
#
# Preferred path: $XDG_CONFIG_HOME/agent-utilities/inventory.yml
#   (~/.config/agent-utilities/inventory.yml on a typical Linux/macOS host).
#   A legacy inventory.yaml at the same location is still read if no .yml exists.
#
# Two layouts are accepted: Ansible-style (recommended, shown below) and flat.

all:
  # Group-level defaults applied to every host unless a host overrides them.
  vars:
    ansible_user: operator                        # reserved example SSH user
    ansible_ssh_private_key_file: ~/.ssh/id_rsa   # default private key
    ansible_ssh_known_hosts_file: ~/.ssh/known_hosts  # verified server keys

  # Hosts attached directly to `all`.
  hosts:
    edge-node:
      ansible_host: 192.0.2.13                     # reserved example address
    gpu-node:
      ansible_host: 192.0.2.16
      ansible_user: ml                             # override the group default
      ansible_port: 2222                           # SSH port (default 22)

  # Named sub-groups. Pass `--group storage` (CLI) or `group` (MCP) to scope ops.
  children:
    storage:
      vars:
        ansible_user: admin                        # group-scoped default
      hosts:
        nas:
          ansible_host: 192.0.2.10
          # ansible_ssh_pass_ref: vault://ssh/system-a/password
          # ansible_ssh_common_args: "-J jump@bastion"  # jump host / extra SSH args

# ------------------------------------------------------------------------------
# Recognized per-host keys (Ansible alias -> native key -> meaning):
#   ansible_host                 -> hostname              IP / DNS name (defaults to alias)
#   ansible_user                 -> user                  SSH user
#   ansible_port                 -> port                  SSH port (default 22)
#   ansible_ssh_private_key_file -> identity_file/key_path  path to the private key
#   ansible_ssh_pass_ref         -> password_ref          secret-manager reference
#   ansible_ssh_known_hosts_file -> known_hosts_file      verified server-key trust store
#   ansible_ssh_common_args      -> proxy_command         extra SSH args / jump host
#
# Flat layout (no `all:` wrapper) is also accepted:
#   edge-node:
#     hostname: 192.0.2.13
#     user: operator
#     identity_file: ~/.ssh/id_rsa
#     known_hosts_file: ~/.ssh/known_hosts
"""

# Per-host keys that must resolve to a value for a host to be usable.
_REQUIRED_HOST_FIELDS = ("hostname", "user")


def _inventory_init(dest: str, force: bool) -> int:
    """Write the commented template to ``dest`` unless it already exists."""
    if os.path.exists(dest) and not force:
        print(
            f"Refusing to overwrite existing inventory: {dest}\n"
            f"Re-run with --force to overwrite, or edit the file directly.",
            file=sys.stderr,
        )
        return 1
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "w") as f:
        f.write(INVENTORY_TEMPLATE)
    print(f"Wrote inventory template to {dest}")
    print("Edit it to define your hosts, then run: tunnel-manager inventory doctor")
    return 0


def _inventory_doctor(inventory: str, fix: bool) -> int:
    """Validate the inventory; return a non-zero exit code on hard errors."""
    xdg_config = setting("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    config_dir = os.path.join(xdg_config, "agent-utilities")
    yml_path = os.path.join(config_dir, "inventory.yml")
    yaml_path = os.path.join(config_dir, "inventory.yaml")

    problems: list[str] = []

    # Legacy-migration check: a .yaml exists but no .yml at the shared location.
    if os.path.exists(yaml_path) and not os.path.exists(yml_path):
        if fix:
            os.rename(yaml_path, yml_path)
            print("Migrated legacy inventory configuration")
            inventory = yml_path
        else:
            print(
                f"NOTE: legacy {yaml_path} found but no {yml_path}.\n"
                f"  Fix: re-run `tunnel-manager inventory doctor --fix` to migrate to .yml.",
            )

    if not os.path.exists(inventory):
        print(
            f"ERROR: inventory file not found: {inventory}\n"
            f"  Fix: run `tunnel-manager inventory init` to create a template.",
            file=sys.stderr,
        )
        return 1

    try:
        with open(inventory) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(
            f"ERROR: {inventory} is not valid YAML: {type(e).__name__}\n"
            f"  Fix: correct the YAML syntax (check indentation and colons).",
            file=sys.stderr,
        )
        return 1

    if not isinstance(raw, dict):
        print(
            f"ERROR: {inventory} must be a YAML mapping at the top level, got "
            f"{type(raw).__name__}.",
            file=sys.stderr,
        )
        return 1

    # Reuse the existing parsing so doctor sees exactly what the runtime sees.
    hm = HostManager(config_file=inventory)
    hosts = hm.hosts

    if not hosts:
        problems.append(
            "no hosts defined — add at least one host under `all.hosts` or a child group."
        )

    for alias, entry in hosts.items():
        if not isinstance(entry, dict):
            problems.append(f"host '{alias}': entry is not a mapping.")
            continue
        for field in _REQUIRED_HOST_FIELDS:
            value = entry.get(field)
            if value is None or value == "":
                hint = (
                    "set `ansible_host` (or `hostname`)"
                    if field == "hostname"
                    else "set `ansible_user` (or a group-level `vars.ansible_user`)"
                )
                problems.append(
                    f"host '{alias}': missing required field '{field}' — {hint}."
                )

    # Groups must reference hosts that actually parse into the inventory.
    if isinstance(raw.get("all"), dict):
        children = raw["all"].get("children", {}) or {}
        for group_name, group_data in children.items():
            if not isinstance(group_data, dict):
                problems.append(f"group '{group_name}': entry is not a mapping.")
                continue
            for ghost in group_data.get("hosts", {}) or {}:
                if ghost not in hosts:
                    problems.append(
                        f"group '{group_name}': references host '{ghost}' which did "
                        f"not parse into the inventory — check its definition."
                    )

    if problems:
        print(f"Inventory validation found {len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(f"Inventory validation succeeded ({len(hosts)} host(s)).")
    return 0


def _inventory_show(inventory: str) -> int:
    """Print a privacy-safe inventory count summary."""
    print("Inventory configuration resolved")
    if not os.path.exists(inventory):
        print("  (file does not exist — run `tunnel-manager inventory init`)")
        return 0

    hm = HostManager(config_file=inventory)
    hosts = hm.hosts
    print(f"Hosts configured: {len(hosts)}")

    try:
        with open(inventory) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError:
        raw = {}
    if isinstance(raw.get("all"), dict):
        children = raw["all"].get("children", {}) or {}
        if children:
            print(f"Groups configured: {len(children)}")
    return 0


def tunnel_manager():
    print(f"tunnel_manager v{__version__}", file=sys.stderr)
    parser = argparse.ArgumentParser(description="Tunnel Manager CLI")
    parser.add_argument("--log-file", help="Log to this file (default: console output)")

    default_inventory = setting("TUNNEL_INVENTORY") or default_inventory_path()

    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup-all", help="Setup passwordless for all")
    setup_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    setup_parser.add_argument(
        "--shared-key-path",
        default="~/.ssh/id_shared",
        help="Path to shared private key",
    )
    setup_parser.add_argument(
        "--key-type",
        choices=["rsa", "ed25519"],
        default="ed25519",
        help="Key type to generate (rsa or ed25519, default: ed25519)",
    )
    setup_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    setup_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    setup_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    run_parser = subparsers.add_parser("run-command", help="Run command on all")
    run_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    run_parser.add_argument("--remote-command", help="Shell command to run")
    run_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    run_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    run_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Command timeout in seconds (default: 60)",
    )

    copy_parser = subparsers.add_parser("copy-config", help="Copy SSH config to all")
    copy_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    copy_parser.add_argument(
        "--local-config-path", default="~/.ssh/config", help="Local SSH config path"
    )
    copy_parser.add_argument(
        "--remote-config-path",
        default="~/.ssh/config",
        help="Remote path (default ~/.ssh/config)",
    )
    copy_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    copy_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    copy_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    rotate_parser = subparsers.add_parser("rotate-key", help="Rotate keys for all")
    rotate_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    rotate_parser.add_argument(
        "--key-prefix",
        default="~/.ssh/id_",
        help="Prefix for new key paths (appends hostname)",
    )
    rotate_parser.add_argument(
        "--key-type",
        choices=["rsa", "ed25519"],
        default="ed25519",
        help="Key type to generate (rsa or ed25519, default: ed25519)",
    )
    rotate_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    rotate_parser.add_argument(
        "--parallel", action="store_true", help="Run in parallel"
    )
    rotate_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    send_parser = subparsers.add_parser(
        "send-file", help="Upload file to all hosts in inventory"
    )
    send_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    send_parser.add_argument("--local-path", help="Local file path to upload")
    send_parser.add_argument("--remote-path", help="Remote destination path")
    send_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    send_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    send_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    receive_parser = subparsers.add_parser(
        "receive-file", help="Download file from all hosts in inventory"
    )
    receive_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    receive_parser.add_argument("--remote-path", help="Remote file path to download")
    receive_parser.add_argument(
        "--local-path-prefix", help="Local directory path prefix to save files"
    )
    receive_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    receive_parser.add_argument(
        "--parallel", action="store_true", help="Run in parallel"
    )
    receive_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    inventory_parser = subparsers.add_parser(
        "inventory", help="Create, validate, or inspect the shared inventory file"
    )
    inventory_sub = inventory_parser.add_subparsers(
        dest="inventory_action", required=True
    )

    inv_init = inventory_sub.add_parser(
        "init", help="Write a commented inventory.yml template to the resolved path"
    )
    inv_init.add_argument(
        "--inventory",
        default=None,
        help="Destination path (default: resolved shared inventory path)",
    )
    inv_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing inventory file instead of refusing",
    )

    inv_doctor = inventory_sub.add_parser(
        "doctor", help="Validate the inventory and report problems with fixes"
    )
    inv_doctor.add_argument(
        "--inventory",
        default=None,
        help="Inventory path to validate (default: resolved shared inventory path)",
    )
    inv_doctor.add_argument(
        "--fix",
        action="store_true",
        help="Migrate a legacy inventory.yaml to inventory.yml when applicable",
    )

    inv_show = inventory_sub.add_parser(
        "show", help="Print the resolved inventory path and a host/group summary"
    )
    inv_show.add_argument(
        "--inventory",
        default=None,
        help="Inventory path to show (default: resolved shared inventory path)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.log_file:
        log_dir = (
            os.path.dirname(os.path.abspath(args.log_file))
            if os.path.dirname(args.log_file)
            else os.getcwd()
        )
        os.makedirs(log_dir, exist_ok=True)
        try:
            logging.basicConfig(
                filename=args.log_file,
                level=logging.DEBUG,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            )
        except PermissionError as e:
            print(
                f"Error: cannot write configured log file ({type(e).__name__})",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    logger = logging.getLogger("Tunnel")
    logger.debug("Starting tunnel automation: command_type=%s", args.command)
    print("Starting tunnel automation", file=sys.stderr)

    if args.command == "inventory":
        target = getattr(args, "inventory", None) or default_inventory_path()
        if args.inventory_action == "init":
            sys.exit(_inventory_init(target, args.force))
        elif args.inventory_action == "doctor":
            sys.exit(_inventory_doctor(target, args.fix))
        elif args.inventory_action == "show":
            sys.exit(_inventory_show(target))

    try:
        if args.command == "setup-all":
            Tunnel.setup_all_passwordless_ssh(
                args.inventory,
                args.shared_key_path,
                args.key_type,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "run-command":
            Tunnel.run_command_on_inventory(
                args.inventory,
                args.remote_command,
                args.group,
                args.parallel,
                args.max_threads,
                timeout=args.timeout,
            )
        elif args.command == "copy-config":
            Tunnel.copy_ssh_config_on_inventory(
                args.inventory,
                args.local_config_path,
                args.remote_config_path,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "rotate-key":
            Tunnel.rotate_ssh_key_on_inventory(
                args.inventory,
                args.key_prefix,
                args.key_type,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "send-file":
            Tunnel.send_file_on_inventory(
                args.inventory,
                args.local_path,
                args.remote_path,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "receive-file":
            Tunnel.receive_file_on_inventory(
                args.inventory,
                args.remote_path,
                args.local_path_prefix,
                args.group,
                args.parallel,
                args.max_threads,
            )
        logger.debug("Automation Complete")
        print("Automation Complete", file=sys.stderr)
    except Exception as e:
        logger.error("Operation failed: error_type=%s", type(e).__name__)
        print(f"Operation failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)


def main():
    tunnel_manager()


if __name__ == "__main__":
    tunnel_manager()
