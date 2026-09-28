import pytest

from server import main, startup


def test_checks_run_in_the_required_order():
    assert [name for name, _ in startup.CHECKS] == [
        "detector rules",
        "command catalog",
        "issue index",
        "signals",
        "corpus generation",
    ]


def test_skeleton_checks_pass():
    startup.run()


def test_first_failure_stops_the_rest():
    ran = []

    def ok(name):
        return lambda: ran.append(name)

    def fail():
        raise FileNotFoundError("/internal/path/detectors.toml")

    checks = [("a", ok("a")), ("b", fail), ("c", ok("c"))]
    with pytest.raises(startup.StartupError) as err:
        startup.run(checks)

    assert ran == ["a"]
    assert str(err.value) == "startup check failed: b"
    assert isinstance(err.value.__cause__, FileNotFoundError)


def test_main_exits_before_serving_when_a_check_fails(monkeypatch):
    def fail():
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
