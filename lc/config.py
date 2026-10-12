"""Load project configuration from config.toml."""

from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python 3.9/3.10

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.toml"


def load():
    """Return the parsed config.toml as a dict."""
    with CONFIG_PATH.open("rb") as f:
        return tomllib.load(f)