import contextvars
import functools
import inspect
import logging
import re
import sys
import time
import traceback
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, NamedTuple, Optional, Set

from google.cloud.logging import Client
from google.cloud.logging_v2 import Logger, Resource
from google.cloud.logging_v2.handlers import CloudLoggingHandler
from starlette.applications import Starlette
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

AsyncPayloadParser = Callable[[Request], Awaitable[Any]]

GCLOUD_LOG_MAX_BYTE_SIZE = 1024 * 246

GAE_REQUEST_CONTEXT: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    'GAE_REQUEST_CONTEXT',
    default=None
)


class TraceContext(NamedTuple):
    """Trace information extracted from incoming request headers."""
    trace_id: Optional[str] = None
    span_id: Optional[str] = None


# Ported from google.cloud.logging_v2.handlers._helpers so behavior matches the official library.
_VERSION_PART = r"(?!ff)[a-f\d]{2}"
_TRACE_ID_PART = r"(?![0]{32})[a-f\d]{32}"
_PARENT_ID_PART = r"(?![0]{16})[a-f\d]{16}"
_FLAGS_PART = r"[a-f\d]{2}"
_TRACEPARENT_RE = re.compile(
    f"^\\s?({_VERSION_PART})-({_TRACE_ID_PART})-({_PARENT_ID_PART})-({_FLAGS_PART})(-.*)?\\s?$"
)

# "TRACE_ID[/SPAN_ID][;o=OPTIONS]"
_XCLOUD_TRACE_RE = re.compile(r"([\w-]+)?(\/?([\w-]+))?(;?o=(\d))?")


def parse_traceparent(header: Optional[str]) -> TraceContext:
    """Parses a W3C `traceparent` header (https://www.w3.org/TR/trace-context/).

    Returns an empty TraceContext if the header is missing or can't be parsed.
    """
    if not header:
        return TraceContext()

    match = _TRACEPARENT_RE.match(header)
    if not match:
        return TraceContext()

    return TraceContext(trace_id=match.group(2), span_id=match.group(3))


def parse_xcloud_trace(header: Optional[str]) -> TraceContext:
    """Parses a legacy `X-Cloud-Trace-Context` header.

    The decimal span id is converted to the 16-char hex form Cloud Logging expects.
    A span id that is not a number, is 0, or is >= 2**64 is dropped; the trace id is kept.
    """
    if not header:
        return TraceContext()

    match = _XCLOUD_TRACE_RE.match(header)
    if not match:
        return TraceContext()

    trace_id = match.group(1)
    span_id = match.group(3)

    try:
        span_int = int(span_id)
        span_id = f"{span_int:016x}" if 0 < span_int < 2 ** 64 else None
    except (ValueError, TypeError):
        span_id = None

    return TraceContext(trace_id=trace_id, span_id=span_id)


def extract_trace_context(headers: Dict[bytes, bytes]) -> TraceContext:
    """Extracts trace info from ASGI headers: `traceparent` first, then the legacy header."""
    ctx = parse_traceparent(headers.get(b"traceparent", b"").decode("latin-1"))
    if ctx.trace_id:
        return ctx

    return parse_xcloud_trace(headers.get(b"x-cloud-trace-context", b"").decode("latin-1"))


def get_gae_context() -> Dict[str, Any]:
    """Retrieves the current GAE request context.

    If the context is not set (e.g., running in a background thread or outside
    the request lifecycle), this returns a new, safe default instance to prevent
    KeyErrors.

    Returns:
        Dict[str, Any]: The context dictionary containing 'trace_id', 'span_id', 'start_time',
        and 'max_log_level'.
    """
    ctx = GAE_REQUEST_CONTEXT.get()
    if ctx is None:
        return {
            'trace_id': None,
            'span_id': None,
            'start_time': time.time(),
            'max_log_level': logging.NOTSET
        }
    return ctx


def inject_gae_request_context(func: Callable) -> Callable:
    """
    Captures the current thread's GAE logging context and wraps the target function
    to ensure the context is injected when executed in a worker thread.

    Use this utility when passing functions to thread pools (like `ThreadPoolExecutor`)
    to ensure that logs generated inside the worker thread are correctly grouped under
    the parent HTTP request trace in Google Cloud Logging. This safely propagates the
    logging context without copying unrelated context variables (like database sessions),
    preventing deadlocks.

    The context is set for the duration of the call only and is reset afterwards, so
    reused pool threads never leak one request's trace into a later, unrelated task.

    Note:
        - Do not use this as a static `@decorator` on a function definition. Decorators
          are evaluated at module import time (before the request exists), so the captured
          context will be empty. Always apply it dynamically at execution time.
        - Only synchronous callables are supported. For an `async def` function the
          context would be set only while the coroutine object is created, not while it
          runs, so it would silently have no effect. Passing a coroutine function raises
          `TypeError`.
        - The request context is shared by reference, not copied. Log levels recorded
          in worker threads therefore contribute to the severity of the parent request
          log, as long as the task logs before the request has finished. Logs emitted
          by tasks that outlive the request are still grouped under the trace, but can
          no longer change the already-emitted request log severity.
        - This is not needed for `starlette.concurrency.run_in_threadpool` or
          `anyio.to_thread.run_sync`, which already copy the full context into the
          worker thread. It is intended for raw `ThreadPoolExecutor` usage.

    Args:
        func (Callable): A synchronous callable to run in a worker thread.

    Returns:
        Callable: A wrapper that runs `func` with the captured GAE context active.

    Raises:
        TypeError: If `func` is a coroutine function.

    Example:
        ```python
        from concurrent.futures import ThreadPoolExecutor
        from fastapi_gae_logging import inject_gae_request_context

        def background_task(payload: dict):
            logging.info(f"Processing {payload}") # This will be grouped correctly!

        with ThreadPoolExecutor(max_workers=5) as pool:
            # Wrap the function exactly at submission time
            pool.submit(inject_gae_request_context(background_task), {"user": 123})
        ```
    """
    if inspect.iscoroutinefunction(func):
        raise TypeError(
            "inject_gae_request_context only supports synchronous callables; "
            f"got coroutine function {getattr(func, '__qualname__', func)!r}. "
            "Async code already runs in the request's context."
        )

    gae_ctx = GAE_REQUEST_CONTEXT.get()

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        token = GAE_REQUEST_CONTEXT.set(gae_ctx)
        try:
            return func(*args, **kwargs)
        finally:
            GAE_REQUEST_CONTEXT.reset(token)

    return wrapper


def bytes_repr(num: float, suffix: str = 'B') -> str:
    """Converts a byte count into a human-readable string.

    Args:
        num (float): The number of bytes.
        suffix (str): The suffix for the unit (default 'B').

    Returns:
        str: A formatted string like '1.2KB' or '4.5MB'.
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def get_real_size(obj: Any, seen: Optional[Set[int]] = None) -> int:
    """Recursively calculates the deep memory footprint of an object.

    Args:
        obj (Any): The object to analyze.
        seen (Optional[set]): A set of object IDs already processed to handle recursion.

    Returns:
        int: The total size in bytes.
    """
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0

    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_real_size(v, seen) for v in obj.values()])
        size += sum([get_real_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_real_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_real_size(i, seen) for i in obj])
    return size


class GaeLogSizeLimitFilter(logging.Filter):
    """Filter to prevent logs from exceeding Google Cloud's size limits.

    Google Cloud Logging has a limit (approx. 256KB) for individual log entries.
    This filter suppresses the structured log if it exceeds the limit and prints
    it to stdout instead to preserve the data.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Evaluates if a log record is within the allowed byte size."""
        record_size = get_real_size(record.msg)
        if record_size > GCLOUD_LOG_MAX_BYTE_SIZE:
            logging.warning(f"Log entry with size {bytes_repr(record_size)} exceeds maximum size "
                            f"of {bytes_repr(GCLOUD_LOG_MAX_BYTE_SIZE)}."
                            f"Dropping logging record originated from: {record.filename}:{record.lineno}. "
                            f"Using print instead, check stdout/stderr for print with timestamp: "
                            f"{datetime.fromtimestamp(record.created).isoformat()}")

            print(
                f"{datetime.fromtimestamp(record.created).isoformat()} [{record.levelname}] | {record.name} | "
                f"{record.pathname}:{record.lineno} | {record.funcName} - {record.getMessage()}\n"
                + (
                    f"\nException:\n{''.join(traceback.format_exception(*record.exc_info))}" if record.exc_info else "")
            )

            return False

        return True


class GaeUrlib3FullPoolFilter(logging.Filter):
    """Filter to suppress noisy 'Connection pool is full' warnings.

    These warnings often originate from Google Cloud internal libraries
    (like storage or firestore) and can flood logs unnecessarily.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Checks if the log record matches known noisy patterns."""
        if "Connection pool is full, discarding connection: appengine.googleapis.internal" in record.getMessage():
            return False

        if "Connection pool is full, discarding connection: storage.googleapis.com" in record.getMessage():
            return False

        return True


class LogInterceptor(logging.Filter):
    """Enriches app logs with GAE trace data for request-log correlation.

    This filter intercepts every log call during a request's lifecycle. It:
    1. Extracts the current trace ID from GAE_REQUEST_CONTEXT.
    2. Updates the max_log_level in the context (used to set parent log severity).
    3. Injects _trace and _span_id into the record so CloudLoggingHandler
       properly groups app logs under the request log.
    """

    def __init__(self, project_id: str, name: str = ""):
        """Initialize the filter.

        Args:
            project_id (str): Google Cloud project ID. Required to format
                the trace string correctly for log grouping.
            name (str): Optional filter name (required by logging.Filter base).
        """
        super().__init__(name)
        self.project_id = project_id

    def filter(self, record: logging.LogRecord) -> bool:
        """Augments the log record with trace info and updates request state."""
        gae_request_context_data = get_gae_context()
        max_log_level = gae_request_context_data['max_log_level']

        if record.levelno > max_log_level:
            gae_request_context_data['max_log_level'] = record.levelno

        trace_id = gae_request_context_data.get("trace_id")
        span_id = gae_request_context_data.get("span_id")

        if trace_id:
            record._trace = f"projects/{self.project_id}/traces/{trace_id}"
            if span_id:
                record._span_id = span_id

        return True


class PayloadParser:
    """Dispatcher for parsing HTTP request bodies based on Content-Type.

    Manages a registry of async parsers. Supports built-in defaults for JSON,
    Forms, and Multipart data, while allowing developers to inject custom
    parsing logic for proprietary media types.
    """
    class Defaults(Enum):
        JSON = "application/json"
        FORM_URLENCODED = "application/x-www-form-urlencoded"
        MULTIPART_FORM = "multipart/form-data"
        PLAIN_TEXT = "text/plain"

    def __init__(
        self,
        builtin_parsers: Optional[List["PayloadParser.Defaults"]] = None,
        custom_parsers: Optional[Dict[str, AsyncPayloadParser]] = None
    ):
        """Initializes the parser registry.

        Args:
            builtin_parsers: List of default parsers to enable.
            custom_parsers: Dictionary mapping mime-types to async parser functions.
        """
        self.parsers: Dict[str, Callable[[Request], Awaitable[Any]]] = {}

        self._builtin_map = {
            self.Defaults.JSON.value: self._parse_json,
            self.Defaults.FORM_URLENCODED.value: self._parse_form_urlencoded,
            self.Defaults.MULTIPART_FORM.value: self._parse_multipart_form,
            self.Defaults.PLAIN_TEXT.value: self._parse_plain_text,
        }

        if builtin_parsers:
            for default in builtin_parsers:
                if default.value in self._builtin_map:
                    self.parsers[default.value] = self._builtin_map[default.value]

        if custom_parsers:
            self.parsers.update(custom_parsers)

    @staticmethod
    async def _parse_json(request: Request) -> Any:
        return await request.json()

    @staticmethod
    async def _parse_form_urlencoded(request: Request) -> Dict[str, Any]:
        form = await request.form()
        return dict(form)

    @staticmethod
    async def _parse_plain_text(request: Request) -> str:
        body_bytes = await request.body()
        return body_bytes.decode('utf-8', errors='replace')

    @staticmethod
    async def _parse_multipart_form(request: Request) -> Dict[str, Any]:
        form: FormData = await request.form()

        form_data = {}
        file_data = []

        for key, value in form.multi_items():
            if isinstance(value, str):
                form_data[key] = value
            else:
                file_data.append({
                    'form_field': key,
                    'filename': getattr(value, 'filename', 'unknown'),
                    'content_type': getattr(value, 'content_type', 'unknown'),
                })

        return {
            'form_data': form_data,
            'file_data': file_data
        }

    def get_parser(self, content_type: str) -> Optional[Callable[[Request], Awaitable[Any]]]:
        """
        Returns the async parser function for the given content type.

        Args:
            content_type (str): The MIME type (e.g., 'application/json').

        Returns:
            Optional[Callable]: The parser function or None if not found.
        """
        return self.parsers.get(content_type)


class GAERequestLogger:
    """Emits the final structured Request Log to Google App Engine.

    This logger is designed to work with FastAPI applications deployed on Google App Engine. It logs
    structured data after each request is handled, including the HTTP request method, URL, status,
    user agent, response size, latency, and remote IP address. The log severity is determined by the
    maximum log level recorded during the request.
    """
    LOG_LEVEL_TO_SEVERITY: Dict[int, str] = {
        logging.NOTSET: 'DEFAULT',
        logging.DEBUG: 'DEBUG',
        logging.INFO: 'INFO',
        logging.WARNING: 'WARNING',
        logging.ERROR: 'ERROR',
        logging.CRITICAL: 'CRITICAL',
    }

    def __init__(self, logger: Logger, resource: Resource, log_payload: bool = False, log_headers: bool = False,
                 builtin_payload_parsers: Optional[List[PayloadParser.Defaults]] = None,
                 custom_payload_parsers: Optional[Dict[str, AsyncPayloadParser]] = None) -> None:
        """Initialize the GAERequestLogger.

        Args:
            logger (Logger): The Google Cloud Logger instance to log requests.
            resource (Resource): The resource associated with the logger.
            log_payload (bool): Whether to log the request payload for certain HTTP methods. Defaults to False.
            log_headers (bool): Whether to log the request headers. Defaults to False.
            builtin_payload_parsers: List of defaults to enable.
            custom_payload_parsers: Dictionary of custom parsers.
        """
        self.logger = logger
        self.resource = resource
        self.log_payload = log_payload
        self.log_headers = log_headers
        self.payload_parsers = PayloadParser(
            builtin_parsers=builtin_payload_parsers,
            custom_parsers=custom_payload_parsers
        )
        self._trace_prefix = f"projects/{logger.project}/traces/"

    def _log_level_to_severity(self, log_level: int) -> str:
        """Converts Python logging levels to Cloud Logging severity strings."""
        return self.LOG_LEVEL_TO_SEVERITY.get(log_level, self.LOG_LEVEL_TO_SEVERITY[logging.NOTSET])

    @staticmethod
    def _truncate_log_on_cap(log_payload: Any, trace: str) -> Any:
        """Truncates payload if it exceeds the GAE size limit to prevent crash."""
        logging_payload_size = get_real_size(log_payload)
        if logging_payload_size > GCLOUD_LOG_MAX_BYTE_SIZE:
            print(f"Request payload that was skipped in parent log with trace {trace}: {log_payload}")
            log_payload = (f"Request logging payload with size {bytes_repr(logging_payload_size)} "
                           f"exceeds maximum size of {bytes_repr(GCLOUD_LOG_MAX_BYTE_SIZE)}, "
                           f"truncating request body payload from log and using print instead."
                           f"Check stdout/stderr for print with trace {trace}.")

        return log_payload

    async def emit_request_log(self, request: Request, response: Response) -> None:
        """Constructs and emits the structured request log.

        This method is called at the end of the request lifecycle. It calculates
        latency, determines the final severity, and sends the log to GCP.
        """
        gae_request_context_data = get_gae_context()

        trace_id = gae_request_context_data.get("trace_id")
        span_id = gae_request_context_data.get("span_id")

        if not trace_id:
            return

        trace = f"{self._trace_prefix}{trace_id}"
        severity = self._log_level_to_severity(log_level=gae_request_context_data['max_log_level'])

        http_request = {
            'requestMethod': request.method,
            'requestUrl': str(request.url),
            'status': response.status_code,
            'userAgent': request.headers.get('User-Agent'),
            'responseSize': response.headers.get('Content-Length'),
            'latency': f'{(time.time() - gae_request_context_data["start_time"]):.6f}s',
            'remoteIp': request.client.host if request.client else None
        }

        logging_payload = {}

        if self.log_headers:
            logging_payload['request_headers'] = dict(request.headers)

        if self.log_payload and request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            content_type = request.headers.get("content-type", "").split(";")[0].strip()
            payload_parser = self.payload_parsers.get_parser(content_type)

            if not payload_parser:
                request_payload = f"Unsupported content type {content_type}. Skipping payload logging."
            else:
                try:
                    request_payload = await payload_parser(request)
                except Exception as e:
                    request_payload = (f"Parser of request payload for "
                                       f"content type {content_type} failed: {e} | {traceback.format_exc()}")

            if request_payload:
                logging_payload['request_payload'] = self._truncate_log_on_cap(request_payload, trace)

        self.logger.log_struct(
            info=logging_payload,
            resource=self.resource,
            trace=trace,
            span_id=span_id,
            http_request=http_request,
            severity=severity
        )


class FastAPIGAELoggingMiddleware:
    """ASGI Middleware for request-response correlation and automated logging.

    This middleware:
    1. Initializes the GAE_REQUEST_CONTEXT at the start of a request.
    2. Caches the request body (allowing multiple reads).
    3. Intercepts the response to capture status code and body.
    4. Triggers the final request log emission.

    Note:
        This middleware caches the entire request body in memory. Use caution
        with large file uploads as this may lead to high memory consumption.
    """

    def __init__(self, app: ASGIApp, logger: GAERequestLogger):
        """Initialize the middleware.

        Args:
            app (ASGIApp): The ASGI application instance.
            logger (GAERequestLogger): The logger instance used to log request data.
        """
        self.app = app
        self.logger = logger

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        """
        Middleware entry point, invoked for each request.

        This method sets up the request context with trace information, start time, and initial log level.
        It then intercepts the response to capture details for logging. In case of exceptions, they are
        logged, and the exception is re-raised.

        Args:
            scope (Scope): The ASGI scope dictionary containing request information.
            receive (Receive): The receive channel for incoming messages.
            send (Send): The send channel for outgoing messages.
        """

        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers: Dict[bytes, bytes] = dict(scope.get("headers", []))
        trace_ctx = extract_trace_context(headers)

        GAE_REQUEST_CONTEXT.set(
            {
                "trace_id": trace_ctx.trace_id,
                "span_id": trace_ctx.span_id,
                "start_time": time.time(),
                "max_log_level": logging.NOTSET,
            }
        )

        # check if we need to log the request payload
        method = scope.get("method", "GET")
        should_cache_body = (
                self.logger.log_payload
                and method in {'POST', 'PUT', 'PATCH', 'DELETE'}
        )

        # if we need to log the request payload, then patch
        # the ASGI receive channel to cache it, so that next consumers
        # can access it normally after our intervention

        if should_cache_body:
            chunks: List[bytes] = []
            more_body = True

            # Consume the stream
            while more_body:
                chunk = await receive()
                # Safety Check: Handle client disconnects during upload
                # If client disconnects, we just forward that message immediately
                # and stop trying to buffer.
                if chunk["type"] == "http.disconnect":
                    async def disconnect_receive(chunk_local: Message = chunk) -> Message:
                        return chunk_local
                    patched_receive = disconnect_receive
                    break
                # Standard payload chunk handling
                chunks.append(chunk.get("body", b""))
                more_body = chunk.get("more_body", False)
            else:
                # We reached more_body=False safely and while loop did not break.
                # Stream consumed successfully.
                body = b"".join(chunks)

                # Create a closure that replays the full body as a single message.
                # When next consumers call it (FastAPI/Starllette handlers),
                # they re-consume the full body instantly from the cached closure

                async def receive_cache(body_local: bytes = body) -> Message:
                    return {
                        "type": "http.request",
                        "body": body_local,
                        "more_body": False
                    }
                patched_receive = receive_cache
        else:
            # If payload log is disabled, leave the original receive channel intact
            patched_receive = receive

        request = Request(scope, receive=patched_receive)
        # mock response object to pass into logger.emit_request_log
        # after the response from app is over
        response = Response(status_code=500)

        # spoof response from server to copy the status code
        # and inject it into the mock response closure initiated
        async def send_spoof_wrapper(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                response.status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, patched_receive, send_spoof_wrapper)
        except Exception as e:
            if not isinstance(e, HTTPException):
                logging.exception(e)
            raise e
        finally:
            await self.logger.emit_request_log(request, response)


class FastAPIGAELoggingHandler(CloudLoggingHandler):
    """Primary handler for enabling GAE-structured logging in FastAPI/Starlette.

    This class extends the standard CloudLoggingHandler to automatically
    inject the necessary middleware and logging filters into the application.
    """

    REQUEST_LOGGER_SUFFIX: str = '-request-logger'

    def __init__(
            self,
            app: Starlette,
            client: Client,
            request_logger_name: Optional[str] = None,
            log_payload: bool = False,
            log_headers: bool = False,
            builtin_payload_parsers: Optional[List[PayloadParser.Defaults]] = None,
            custom_payload_parsers: Optional[Dict[str, AsyncPayloadParser]] = None,
            *args, **kwargs
    ) -> None:
        """
        Initialize the handler.

        Args:
            app: The FastAPI or Starlette application instance.
            client: The Google Cloud Logging Client.
            request_logger_name: Optional name for the request logger (defaults to project ID).
            log_payload: Whether to log request bodies.
            log_headers: Whether to log request headers.
            builtin_payload_parsers: List of defaults to enable.
            custom_payload_parsers: Dictionary of custom parsers.
            *args, **kwargs: Arguments passed to CloudLoggingHandler.
        """
        super().__init__(client, *args, **kwargs)
        self.app = app
        self._log_interceptor = LogInterceptor(project_id=client.project)
        self.app.add_middleware(
            middleware_class=FastAPIGAELoggingMiddleware,
            logger=GAERequestLogger(
                logger=self.client.logger(
                    name=request_logger_name or f"{self.client.project}{self.REQUEST_LOGGER_SUFFIX}",
                    resource=self.resource
                ),
                resource=self.resource,
                log_payload=log_payload,
                log_headers=log_headers,
                builtin_payload_parsers=builtin_payload_parsers,
                custom_payload_parsers=custom_payload_parsers
            )
        )
        self.addFilter(self._log_interceptor)

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Custom filter logic that ensures user-added filters are respected
        before applying the internal LogInterceptor for severity propagation.

        This ensures that if a log is dropped by another filter (e.g. noise suppression),
        it does not affect the final request log severity.
        """

        for f in self.filters:

            if f is self._log_interceptor:
                continue

            if hasattr(f, 'filter'):
                result = f.filter(record)
            else:
                result = f(record)

            if not result:
                return False

            if isinstance(result, logging.LogRecord):
                record = result

        result = self._log_interceptor.filter(record)

        if not result:
            return False

        return True
