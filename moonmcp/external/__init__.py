"""Optional integration with best-in-class security CLIs.

MoonMCP never *requires* these binaries.  When they are present on ``PATH`` it
wraps them and parses their structured output; when they are absent it returns a
clear, actionable message and points the caller at the native stdlib tool that
covers the same ground.
"""
