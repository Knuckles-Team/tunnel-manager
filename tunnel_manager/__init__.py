#!/usr/bin/env python
# coding: utf-8

from tunnel_manager.tunnel_manager import (
    Tunnel,
)
from tunnel_manager.tunnel_manager_mcp import tunnel_manager_mcp

"""
tunnel-manager

Create SSH tunnels to your remote hosts!
"""


__all__ = ["tunnel_manager_mcp", "Tunnel"]
