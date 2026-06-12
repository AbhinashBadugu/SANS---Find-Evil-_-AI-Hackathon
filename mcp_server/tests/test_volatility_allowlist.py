import pytest

from forensic_mcp.allowlists import validate_volatility_plugin


def test_windows_info_allowed():
    assert validate_volatility_plugin("windows.info") == "windows.info"


def test_malfind_rejected_in_v1():
    with pytest.raises(ValueError):
        validate_volatility_plugin("windows.malfind", full=False)


def test_malfind_allowed_in_full():
    assert validate_volatility_plugin("windows.malfind", full=True) == "windows.malfind"


def test_unknown_plugin_rejected():
    with pytest.raises(ValueError):
        validate_volatility_plugin("windows.totally_made_up", full=True)
