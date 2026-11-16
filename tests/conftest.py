import pytest

from fastapi_gae_logging.fastapi_gae_logging import GAE_REQUEST_CONTEXT


@pytest.fixture(autouse=True)
def isolated_gae_context():
    """Every test starts with no GAE context and leaves none behind."""
    token = GAE_REQUEST_CONTEXT.set(None)
    yield
    GAE_REQUEST_CONTEXT.reset(token)


@pytest.fixture
def gae_ctx():
    """A populated request context, active in the current thread."""
    ctx = {
        "trace_id": "3be23674214b19a57167366852e57564",
        "span_id": "f9be92ed930ba3c3",
        "start_time": 0.0,
        "max_log_level": 0,
    }
    GAE_REQUEST_CONTEXT.set(ctx)
    return ctx
