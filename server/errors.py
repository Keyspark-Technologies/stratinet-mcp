from common.validate import ToolInputError

MESSAGES = {
    "missing_field": "A required field is missing.",
    "invalid_value": "A field has a value of the wrong type or form.",
    "unknown_field": "The request contains a field this tool does not accept.",
    "input_too_large": "The input is larger than this tool accepts.",
    "unsupported_vendor": "This vendor is not supported by this tool.",
    "unsupported_symptom": "This symptom is not supported by this tool.",
    "malformed_cve_id": "The CVE id is not in the form CVE-YYYY-NNNN.",
    "invalid_feature_fact": "A feature fact does not apply to this feature on this vendor.",
    "version_unparseable": "The version string could not be parsed.",
    "internal_error": "The tool could not complete this request.",
    "busy": "The server is busy with other requests. Try again shortly.",
}

HTTP_MESSAGES = {
    "unauthorized": "A valid API key is required.",
    "rate_limited": "Too many requests for this API key. Try again later.",
    "unavailable": "The service is temporarily unavailable.",
}


def http_error_payload(code: str) -> dict:
    return {"error": {"code": code, "message": HTTP_MESSAGES[code]}}


class ServerBusy(Exception):
    pass


def error_payload(exc: Exception) -> dict:
    if isinstance(exc, ServerBusy):
        return {"error": {"code": "busy", "message": MESSAGES["busy"]}}
    if not isinstance(exc, ToolInputError) or exc.code not in MESSAGES:
        return {"error": {"code": "internal_error", "message": MESSAGES["internal_error"]}}
    error: dict = {"code": exc.code, "message": MESSAGES[exc.code]}
    if exc.field is not None:
        error["field"] = exc.field
    if exc.supported is not None:
        error["supported"] = sorted(exc.supported)
    return {"error": error}
