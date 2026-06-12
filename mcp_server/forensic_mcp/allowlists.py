"""The approved list of Volatility plugins. Anything not here is refused.

v1 starts with only windows.info (the vertical slice). Flip `full=True`
once the slice is proven to unlock the wider set."""

VOLATILITY_PLUGIN_ALLOWLIST_V1 = {
    "windows.info",
}

VOLATILITY_PLUGIN_ALLOWLIST_FULL = {
    "windows.info",
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.malfind",
    "windows.svcscan",
    "windows.dlllist",
    "windows.handles",
}


def validate_volatility_plugin(plugin: str, full: bool = False) -> str:
    allowed = VOLATILITY_PLUGIN_ALLOWLIST_FULL if full else VOLATILITY_PLUGIN_ALLOWLIST_V1
    if plugin not in allowed:
        raise ValueError(f"Volatility plugin not allowed: {plugin}")
    return plugin
