"""CDP Network Audit package.

Expose a minimal public surface so the package can be imported cleanly while
keeping side effects (like logging setup) behind the CLI entry point.
"""

from __future__ import annotations

try:
	from importlib.metadata import PackageNotFoundError, version
except ImportError:  # Python < 3.8
	PackageNotFoundError = Exception  # type: ignore[misc,assignment]

	def version(_name: str) -> str:  # type: ignore[override]
		raise PackageNotFoundError


def main() -> None:
	"""Run the CLI entry point when invoked programmatically."""
	from .cli import main as _main

	_main()


try:
	from .__about__ import __version__ as _about_version
except Exception:
	_about_version = None

if _about_version:
	__version__ = _about_version
else:
	try:
		__version__ = version("cdp-network-audit")
	except PackageNotFoundError:
		__version__ = "0+local"


__all__ = ["__version__", "main"]
