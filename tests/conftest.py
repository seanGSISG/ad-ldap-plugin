"""Test bootstrap.

The server modules live as flat top-level modules under ``mcp/`` (no
``__init__.py`` — see pyproject for why). Put that directory on ``sys.path`` so
tests can ``import config`` / ``import ad_client`` directly, exactly the way
``mcp/server.py`` is run.
"""

import os
import sys

_MCP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp")
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)
