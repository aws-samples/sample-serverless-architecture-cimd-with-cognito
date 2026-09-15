"""Puts lambdas/, shared/ and each function directory on sys.path so tests import modules exactly as the Lambdas do."""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[2] / "lambdas"
for p in (root, root / "mcp_server", root / "registrar", root / "cimd_proxy"):
    sys.path.insert(0, str(p))
