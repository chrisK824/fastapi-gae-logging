import logging
from unittest.mock import MagicMock

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from fastapi_gae_logging.fastapi_gae_logging import (
    FastAPIGAELoggingMiddleware,
    GAERequestLogger,
    LogInterceptor,
    get_gae_context,
)

TRACE = "3be23674214b19a57167366852e57564"


@pytest.fixture
def cloud_logger():
    mock = MagicMock()
    mock.project = "proj"
    return mock


@pytest.fixture
def client(cloud_logger):
    async def endpoint(request):
        record = logging.LogRecord("t", logging.WARNING, __file__, 1, "careful", None, None)
        LogInterceptor(project_id="proj").filter(record)
        ctx = get_gae_context()
        return JSONResponse({"trace_id": ctx["trace_id"], "span_id": ctx["span_id"]})

    request_logger = GAERequestLogger(logger=cloud_logger, resource=MagicMock())
    app = Starlette(
        routes=[Route("/", endpoint)],
        middleware=[Middleware(FastAPIGAELoggingMiddleware, logger=request_logger)],
    )
    return TestClient(app)


def test_traceparent_populates_context_and_request_log(client, cloud_logger):
    response = client.get("/", headers={"traceparent": f"00-{TRACE}-f9be92ed930ba3c3-00"})

    assert response.json() == {"trace_id": TRACE, "span_id": "f9be92ed930ba3c3"}
    kwargs = cloud_logger.log_struct.call_args.kwargs
    assert kwargs["trace"] == f"projects/proj/traces/{TRACE}"
    assert kwargs["span_id"] == "f9be92ed930ba3c3"
    assert kwargs["severity"] == "WARNING"  # max level logged during the request
    assert kwargs["http_request"]["status"] == 200


def test_legacy_header_fallback_converts_span_to_hex(client, cloud_logger):
    client.get("/", headers={"x-cloud-trace-context": f"{TRACE}/17995982710090998723;o=1"})

    kwargs = cloud_logger.log_struct.call_args.kwargs
    assert kwargs["trace"] == f"projects/proj/traces/{TRACE}"
    assert kwargs["span_id"] == "f9be92ed930ba3c3"


def test_no_trace_headers_skips_request_log(client, cloud_logger):
    response = client.get("/")

    assert response.json() == {"trace_id": None, "span_id": None}
    cloud_logger.log_struct.assert_not_called()


def test_contexts_do_not_leak_between_requests(client):
    first = client.get("/", headers={"traceparent": f"00-{TRACE}-f9be92ed930ba3c3-00"})
    second = client.get("/")

    assert first.json()["trace_id"] == TRACE
    assert second.json()["trace_id"] is None


def test_sibling_requests_share_trace_but_not_span(client, cloud_logger):
    """Documents current behavior: one upstream trace, two requests, same trace field."""
    client.get("/", headers={"traceparent": f"00-{TRACE}-f9be92ed930ba3c3-00"})
    client.get("/", headers={"traceparent": f"00-{TRACE}-cfc43b512bf81bbd-00"})

    calls = [c.kwargs for c in cloud_logger.log_struct.call_args_list]
    assert calls[0]["trace"] == calls[1]["trace"]
    assert calls[0]["span_id"] != calls[1]["span_id"]
