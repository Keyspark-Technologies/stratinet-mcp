import pytest

from common.redact import InternalMarkerError, assert_no_internal_markers


@pytest.mark.parametrize(
    "leak",
    [
        "Traceback (most recent call last):",
        'File "/srv/x.py", line 12',
        "/app/engines/triage.py",
        "DATABASE_URL=postgres://x",
        "<engines.Thing object at 0x7f00ab12>",
        "KeyError('x')",
    ],
)
def test_internal_markers_are_caught(leak):
    with pytest.raises(InternalMarkerError):
        assert_no_internal_markers({"reason": leak})


@pytest.mark.parametrize("ip", ["10.12.3.2", "172.16.0.1", "192.168.1.1"])
def test_private_addresses_are_caught_by_default(ip):
    with pytest.raises(InternalMarkerError):
        assert_no_internal_markers({"note": f"peer {ip}"})


def test_private_addresses_can_be_allowed_for_caller_quoted_answers():
    assert_no_internal_markers({"line": "10.12.3.2  1  EXSTART/DR"}, check_private_ips=False)


def test_a_clean_answer_passes():
    assert_no_internal_markers(
        {"status": "translated", "command": "get router info bgp summary", "ip": "8.8.8.8"}
    )
