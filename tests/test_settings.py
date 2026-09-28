import pytest

from server.settings import Settings, SettingsError


def test_defaults_when_nothing_is_set():
    s = Settings.from_env({})
    assert s == Settings(port=8000, log_level="INFO", allowed_hosts=("localhost:*", "127.0.0.1:*"))


def test_reads_named_variables():
    s = Settings.from_env(
        {"PORT": "9000", "LOG_LEVEL": "debug", "ALLOWED_HOSTS": " mcp.example.com , a:* "}
    )
    assert s == Settings(port=9000, log_level="DEBUG", allowed_hosts=("mcp.example.com", "a:*"))


@pytest.mark.parametrize(
    ("env", "variable"),
    [
        ({"PORT": "abc"}, "PORT"),
        ({"PORT": "0"}, "PORT"),
        ({"PORT": "70000"}, "PORT"),
        ({"LOG_LEVEL": "LOUD"}, "LOG_LEVEL"),
        ({"ALLOWED_HOSTS": " , "}, "ALLOWED_HOSTS"),
    ],
)
def test_invalid_values_name_the_variable(env, variable):
    with pytest.raises(SettingsError, match=variable):
        Settings.from_env(env)
