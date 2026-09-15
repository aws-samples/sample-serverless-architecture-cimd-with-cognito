"""Lambda entry point for the FastMCP resource server: Mangum adapts the ASGI app to the HTTP API $default stage."""
from app import app
from mangum import Mangum

# HTTP API $default stage: no base path to strip.
handler = Mangum(app, lifespan="auto")
