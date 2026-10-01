from .signals import evaluate


async def observe(
    capability: str,
    facts: dict,
    context: dict | None = None,
    vendor: str = "",
    command: str = "",
    output: str = "",
) -> dict | None:
    return evaluate(capability, facts, context)
