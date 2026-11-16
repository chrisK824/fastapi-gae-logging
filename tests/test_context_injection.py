import functools
import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

from fastapi_gae_logging import inject_gae_request_context
from fastapi_gae_logging.fastapi_gae_logging import (
    GAE_REQUEST_CONTEXT,
    LogInterceptor,
    get_gae_context,
)


def _log_error_through_interceptor() -> logging.LogRecord:
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", None, None)
    LogInterceptor(project_id="proj").filter(record)
    return record


def test_rejects_coroutine_functions():
    async def coro():
        pass

    with pytest.raises(TypeError):
        inject_gae_request_context(coro)

    with pytest.raises(TypeError):
        inject_gae_request_context(functools.partial(coro))


def test_preserves_function_metadata():
    def task():
        """doc"""

    wrapped = inject_gae_request_context(task)
    assert wrapped.__name__ == "task"
    assert wrapped.__doc__ == "doc"


def test_worker_sees_captured_context(gae_ctx):
    with ThreadPoolExecutor(max_workers=1) as pool:
        seen = pool.submit(inject_gae_request_context(GAE_REQUEST_CONTEXT.get)).result()

    assert seen is gae_ctx


def test_context_is_reset_after_task(gae_ctx):
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(inject_gae_request_context(lambda: None)).result()
        # same pooled thread, unwrapped task: must not inherit the previous trace
        leaked = pool.submit(GAE_REQUEST_CONTEXT.get).result()

    assert leaked is None


def test_context_is_reset_even_if_task_raises(gae_ctx):
    def failing():
        raise ValueError("nope")

    with ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(ValueError):
            pool.submit(inject_gae_request_context(failing)).result()
        assert pool.submit(GAE_REQUEST_CONTEXT.get).result() is None


def test_worker_logs_get_trace_and_severity_propagates(gae_ctx):
    with ThreadPoolExecutor(max_workers=1) as pool:
        record = pool.submit(inject_gae_request_context(_log_error_through_interceptor)).result()

        # trace attached to the worker's log record
        assert record._trace == f"projects/proj/traces/{gae_ctx['trace_id']}"
        assert record._span_id == gae_ctx["span_id"]

        # shared dict kept the update after the worker's context was reset
        assert gae_ctx["max_log_level"] == logging.ERROR

        # an unwrapped task later in the same thread sees no context
        assert pool.submit(lambda: get_gae_context()["trace_id"]).result() is None


def test_unwrapped_worker_gets_no_trace(gae_ctx):
    with ThreadPoolExecutor(max_workers=1) as pool:
        record = pool.submit(_log_error_through_interceptor).result()

    assert not hasattr(record, "_trace")
    assert gae_ctx["max_log_level"] == logging.NOTSET
