import logging
import re
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from fastapi_gae_logging import inject_gae_request_context
from fastapi_gae_logging.fastapi_gae_logging import (
    _UPSTREAM_SPAN_ID_LABEL,
    _UPSTREAM_TRACE_ID_LABEL,
    GAE_REQUEST_CONTEXT,
    FastAPIGAELoggingMiddleware,
    GAERequestLogger,
    LogInterceptor,
    get_gae_context,
)

TRACE = "3be23674214b19a57167366852e57564"
HEX32 = re.compile(r"^[0-9a-f]{32}$")


def sibling_headers(span: str) -> dict:
    return {"traceparent": f"00-{TRACE}-{span}-01"}


def _log_through_interceptor() -> logging.LogRecord:
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "careful", None, None)
    LogInterceptor(project_id="proj").filter(record)
    return record


@pytest.fixture
def cloud_logger():
    mock = MagicMock()
    mock.project = "proj"
    return mock


@pytest.fixture
def make_client(cloud_logger):
    def _make(isolate_trace: bool) -> TestClient:
        async def endpoint(request):
            record = _log_through_interceptor()
            ctx = get_gae_context()
            return JSONResponse({
                "trace_id": ctx["trace_id"],
                "record_trace": getattr(record, "_trace", None),
                "record_span": getattr(record, "_span_id", None),
                "record_labels": getattr(record, "_labels", None),
            })

        request_logger = GAERequestLogger(logger=cloud_logger, resource=MagicMock())
        app = Starlette(
            routes=[Route("/", endpoint)],
            middleware=[Middleware(FastAPIGAELoggingMiddleware, logger=request_logger,
                                   isolate_trace=isolate_trace)],
        )
        return TestClient(app)
    return _make


def test_isolation_off_changes_nothing(make_client, cloud_logger):
    body = make_client(False).get("/", headers=sibling_headers("f9be92ed930ba3c3")).json()

    assert body["trace_id"] == TRACE
    assert body["record_labels"] is None
    kwargs = cloud_logger.log_struct.call_args.kwargs
    assert kwargs["trace"] == f"projects/proj/traces/{TRACE}"
    assert kwargs["span_id"] == "f9be92ed930ba3c3"
    assert kwargs["labels"] is None


def test_siblings_get_distinct_traces_and_keep_upstream_trace_in_label(make_client, cloud_logger):
    client = make_client(True)
    span_a = "f9be92ed930ba3c3"
    span_b = "cfc43b512bf81bbd"
    a = client.get("/", headers=sibling_headers(span_a)).json()
    b = client.get("/", headers=sibling_headers(span_b)).json()

    assert HEX32.match(a["trace_id"])
    assert HEX32.match(b["trace_id"])
    assert a["trace_id"] != b["trace_id"]

    # app log
    assert a["record_trace"] == f"projects/proj/traces/{a['trace_id']}"
    assert a["record_labels"] is not None
    assert a["record_labels"] == {_UPSTREAM_TRACE_ID_LABEL: TRACE, _UPSTREAM_SPAN_ID_LABEL: span_a}
    assert a["record_span"] is None

    # request logs
    first, second = [c.kwargs for c in cloud_logger.log_struct.call_args_list]
    assert first["trace"] == a["record_trace"]
    assert first["trace"] != second["trace"]
    assert first["labels"][_UPSTREAM_TRACE_ID_LABEL] == second["labels"][_UPSTREAM_TRACE_ID_LABEL] == TRACE
    assert first["labels"][_UPSTREAM_SPAN_ID_LABEL] == span_a
    assert second["labels"][_UPSTREAM_SPAN_ID_LABEL] == span_b
    assert first["span_id"] is None


def test_isolation_without_trace_headers_still_emits_request_log(make_client, cloud_logger):
    body = make_client(True).get("/").json()

    assert HEX32.match(body["trace_id"])
    assert body["record_labels"] is None  # nothing upstream to preserve
    cloud_logger.log_struct.assert_called_once()
    assert cloud_logger.log_struct.call_args.kwargs["labels"] is None


def test_worker_logs_carry_isolated_trace_and_label():
    GAE_REQUEST_CONTEXT.set({
        "trace_id": "a" * 32, "span_id": None, "labels": {_UPSTREAM_TRACE_ID_LABEL: TRACE},
        "start_time": 0.0, "max_log_level": logging.NOTSET,
    })

    with ThreadPoolExecutor(max_workers=1) as pool:
        record = pool.submit(inject_gae_request_context(_log_through_interceptor)).result()

    assert record._trace == f"projects/proj/traces/{'a' * 32}"
    assert record._labels == {_UPSTREAM_TRACE_ID_LABEL: TRACE}
