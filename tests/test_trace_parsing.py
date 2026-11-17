import pytest

from fastapi_gae_logging.fastapi_gae_logging import (
    TraceContext,
    extract_trace_context,
    parse_traceparent,
    parse_xcloud_trace,
)

TRACE = "3be23674214b19a57167366852e57564"
SPAN_HEX = "f9be92ed930ba3c3"


@pytest.mark.parametrize("header,expected", [
    (f"00-{TRACE}-{SPAN_HEX}-00", (TRACE, SPAN_HEX)),
    (f"00-{TRACE}-{SPAN_HEX}-01", (TRACE, SPAN_HEX)),
    (f" 00-{TRACE}-{SPAN_HEX}-01 ", (TRACE, SPAN_HEX)),
    (f"01-{TRACE}-{SPAN_HEX}-01-extra", (TRACE, SPAN_HEX)),
    (f"00-{TRACE}-{SPAN_HEX}-01-extra", (TRACE, SPAN_HEX)),
    (f"ff-{TRACE}-{SPAN_HEX}-01", (None, None)),
    (f"00-{'0' * 32}-{SPAN_HEX}-01", (None, None)),
    (f"00-{TRACE}-{'0' * 16}-01", (None, None)),
    (f"00-{TRACE.upper()}-{SPAN_HEX}-01", (None, None)),
    (f"00-{TRACE[:-1]}-{SPAN_HEX}-01", (None, None)),
    ("garbage", (None, None)),
    ("", (None, None)),
    (None, (None, None)),
])
def test_parse_traceparent(header, expected):
    assert tuple(parse_traceparent(header)) == expected


@pytest.mark.parametrize("header,expected", [
    (f"{TRACE}/17995982710090998723;o=1", (TRACE, f"{17995982710090998723:016x}")),
    (f"{TRACE}/17995982710090998723", (TRACE, f"{17995982710090998723:016x}")),
    (f"{TRACE}/1;o=0", (TRACE, "0000000000000001")),
    (f"{TRACE}/1;x=y;o=1", (TRACE, "0000000000000001")),  # official quirk
    (f"{TRACE};o=1", (TRACE, None)),
    (TRACE, (TRACE, None)),
    (f"{TRACE}/0", (TRACE, None)),
    (f"{TRACE}/{2 ** 64}", (TRACE, None)),
    (f"{TRACE}/notanumber", (TRACE, None)),
    (f"{TRACE}/-5", (TRACE, None)),
    ("", (None, None)),
    (None, (None, None)),
])
def test_parse_xcloud_trace(header, expected):
    assert tuple(parse_xcloud_trace(header)) == expected


def test_extract_prefers_traceparent_and_falls_back():
    other = "a" * 32
    headers = {
        b"traceparent": f"00-{TRACE}-{SPAN_HEX}-00".encode(),
        b"x-cloud-trace-context": f"{other}/1".encode(),
    }
    assert extract_trace_context(headers).trace_id == TRACE

    headers[b"traceparent"] = b"garbage"
    ctx = extract_trace_context(headers)
    assert (ctx.trace_id, ctx.span_id) == (other, "0000000000000001")

    assert extract_trace_context({}) == TraceContext()


def test_real_world_headers_from_production():
    """Both requests from the shared-trace incident carry the same trace id."""
    headers = {
        b"traceparent": b"00-3be23674214b19a57167366852e57564-cfc43b512bf81bbd-00",
        b"x-cloud-trace-context": b"3be23674214b19a57167366852e57564/14971156281102441405",
    }
    ctx = extract_trace_context(headers)
    assert ctx.trace_id == TRACE
    assert ctx.span_id == "cfc43b512bf81bbd"
