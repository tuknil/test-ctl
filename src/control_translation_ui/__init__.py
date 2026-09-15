"""Demo UI service.

A separate deployable from the capability API. It serves the static demo
assets and publishes the API location to the browser; it never proxies API
traffic and holds no capability state or credentials.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
