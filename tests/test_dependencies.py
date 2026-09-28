from importlib.metadata import version


def test_mcp_sdk_is_the_pinned_version():
    assert version("mcp") == "2.2.0"
