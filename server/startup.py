import logging
from collections.abc import Callable, Sequence

logger = logging.getLogger(__name__)


class StartupError(Exception):
    pass


def load_detector_rules() -> None:
    _not_wired("detector rules")


def warm_command_catalog() -> None:
    _not_wired("command catalog")


def warm_issue_index() -> None:
    _not_wired("issue index")


def import_signals() -> None:
    _not_wired("signals")


def check_corpus_generation() -> None:
    _not_wired("corpus generation")


def _not_wired(name: str) -> None:
    logger.warning("startup check %r is not wired yet", name)


CHECKS: tuple[tuple[str, Callable[[], None]], ...] = (
    ("detector rules", load_detector_rules),
    ("command catalog", warm_command_catalog),
    ("issue index", warm_issue_index),
    ("signals", import_signals),
    ("corpus generation", check_corpus_generation),
)


def run(checks: Sequence[tuple[str, Callable[[], None]]] | None = None) -> None:
    for name, check in CHECKS if checks is None else checks:
        try:
            check()
        except Exception as exc:
            raise StartupError(f"startup check failed: {name}") from exc
        logger.info("startup check passed: %s", name)
