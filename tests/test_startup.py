import shutil

import pytest

from server import main, startup

DATA_CHECKS = [check for name, check in startup.CHECKS if name != "corpus generation"]


def test_checks_run_in_the_required_order():
    assert [name for name, _ in startup.CHECKS] == [
        "detector rules",
        "command catalog",
        "issue index",
        "signals",
        "corpus generation",
    ]


@pytest.mark.parametrize("check", DATA_CHECKS)
def test_each_data_check_passes_on_a_valid_bundle(check, fixture_data_dir):
    check(fixture_data_dir)


@pytest.mark.parametrize("check", DATA_CHECKS)
def test_each_data_check_fails_on_missing_data(check, tmp_path):
    with pytest.raises(Exception):  # noqa: B017
        check(tmp_path)


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("rules/detectors.toml", "[features.x]\nlabel = 'x'\n"),
        ("sop/vendor_commands.yaml", "vendor_commands: []\n"),
        ("sop/capabilities.yaml", "capabilities:\n- {kind: check}\n"),
        ("sop/issues/ospf-neighbor-down.yaml", "issue:\n  key: something-else\n"),
        ("sop/signals.yaml", "{}\n"),
    ],
)
def test_a_broken_file_stops_startup(fixture_data_dir, tmp_path, path, content):
    root = tmp_path / "bundle"
    shutil.copytree(fixture_data_dir, root)
    (root / path).write_text(content)
    with pytest.raises(startup.StartupError):
        startup.run(checks=[c for c in startup.CHECKS if c[0] != "corpus generation"], root=root)


def test_no_corpus_means_no_start(fixture_data_dir):
    with pytest.raises(startup.StartupError, match="corpus generation"):
        startup.run(root=fixture_data_dir)


def test_first_failure_stops_the_rest(tmp_path):
    ran = []

    def ok(name):
        return lambda root: ran.append(name)

    def fail(root):
        raise FileNotFoundError("/internal/path/detectors.toml")

    checks = [("a", ok("a")), ("b", fail), ("c", ok("c"))]
    with pytest.raises(startup.StartupError) as err:
        startup.run(checks, root=tmp_path)

    assert ran == ["a"]
    assert str(err.value) == "startup check failed: b"
    assert isinstance(err.value.__cause__, FileNotFoundError)


def test_main_exits_before_serving_when_a_check_fails(monkeypatch):
    def fail(root):
        raise RuntimeError("no current generation")

    monkeypatch.setattr(startup, "CHECKS", (("corpus generation", fail),))
    monkeypatch.setattr(main.uvicorn, "run", lambda *a, **k: pytest.fail("server started"))

    with pytest.raises(SystemExit) as exit_:
        main.main()
    assert exit_.value.code == 1


def test_main_exits_on_invalid_settings(monkeypatch, capsys):
    monkeypatch.setenv("PORT", "not-a-port")
    monkeypatch.setattr(main.uvicorn, "run", lambda *a, **k: pytest.fail("server started"))

    with pytest.raises(SystemExit) as exit_:
        main.main()
    assert exit_.value.code == 1
    assert "PORT" in capsys.readouterr().err
