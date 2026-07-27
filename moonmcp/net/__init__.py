"""Standard-library networking primitives for MoonMCP.

Everything here is async-friendly (blocking stdlib calls are wrapped with
``asyncio.to_thread``) and honours a shared token-bucket rate limiter so that
recon traffic stays polite.
"""
