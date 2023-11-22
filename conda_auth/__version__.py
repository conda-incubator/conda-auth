try:
    # Only available for releases
    from ._version import __version__, __version_tuple__
except ImportError:
    # Shown during development
    __version__ = "0.0.0.dev0"
    __version_tuple__ = ("0.0.0", "dev0")
