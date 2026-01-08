import logging
import time
import contextvars
import re
import sys
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any, Callable, List, Awaitable
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.datastructures import FormData, UploadFile
from starlette.responses import Response
from starlette.requests import Request
from google.cloud.logging import Client
from google.cloud.logging_v2.handlers import CloudLoggingHandler
from google.cloud.logging_v2 import Resource, Logger
import traceback


GAE_REQUEST_CONTEXT: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    'GAE_REQUEST_CONTEXT',
    default=None
)


def get_gae_context() -> Dict[str, Any]:
    """
    Retrieves the current GAE request context.
    If not set (e.g., in a background thread), returns a new safe default instance.
    """
    ctx = GAE_REQUEST_CONTEXT.get()
    if ctx is None:
        return {
            'trace': None,
            'start_time': time.time(),
            'max_log_level': logging.NOTSET
        }
    return ctx


def bytes_repr(num, suffix='B'):
    """Converts a byte count into a human-readable string (e.g., 1.2KB, 4.5MB)."""
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def get_real_size(obj, seen=None):
    """
    Recursively finds the total memory footprint (deep size) of an object 
    and its members in bytes.
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
    """
    Logging filter to manage the log message size based on the
    maximum log message size allowed by google cloud logging.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records based on the maximum log message size allowed by google cloud logging.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to allow the log record, False to suppress it.
        """
        gcloud_log_max_bytes = 1024 * 246
        record_size = get_real_size(record.msg)
        if record_size > gcloud_log_max_bytes:
            logging.warning(f"Log entry with size {bytes_repr(record_size)} exceeds maximum size "
                            f"of {bytes_repr(gcloud_log_max_bytes)}."
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
    """
    Logging filter to suppress noisy 'Connection pool is full' warning logs
    from Google Cloud and App Engine internal libraries.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter noisy 'Connection pool is full' warning logs
        from Google Cloud and App Engine internal libraries.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to allow the log record, False to suppress it.
        """
        if "Connection pool is full, discarding connection: appengine.googleapis.internal" in record.getMessage():
            return False

        if "Connection pool is full, discarding connection: storage.googleapis.com" in record.getMessage():
            return False

        return True


class LogInterceptor(logging.Filter):
    """
    Logging filter to group logs of a given request and set the maximum log level
    lifecycle for an ASGI app deployed in Google App Engine, using context management and trace.

    Enriches individual LogRecords with GAE-specific trace and span IDs.

    This filter intercepts every log call during a request's lifecycle. It:
    1. Extracts the current trace ID from GAE_REQUEST_CONTEXT.
    2. Updates the max_log_level in the context (used to set parent log severity).
    3. Injects _trace and _span_id into the record so CloudLoggingHandler
       properly groups app logs under the request log.
    """
    def __init__(self, name: str = "", project_id: str | None = None):
        """
        Initialize the filter.

        Args:
            name (str): Optional filter name (required by logging.Filter base).
            project_id (str | None): Optional Google Cloud project ID to use in trace formatting.
        """
        super().__init__(name)
        self.project_id = project_id

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records based on the maximum log level set in the request lifecycle.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to allow the log record, False to suppress it.
        """

        gae_request_context_data = get_gae_context()
        max_log_level = gae_request_context_data['max_log_level']

        if record.levelno > max_log_level:
            gae_request_context_data['max_log_level'] = record.levelno

        trace = gae_request_context_data['trace']

        if trace:
            split_header = trace.split('/', 1)
            record._trace = f"projects/{self.project_id}/traces/{split_header[0]}"
            record._span_id = re.findall(r'^\w+', split_header[1])[0]

        return True


class PayloadParser:
    """
    Dispatcher for parsing HTTP request bodies based on Content-Type.

    This class manages a registry of async parsers. It supports built-in
    defaults for JSON, Forms, and Multipart data, while allowing developers
    to inject custom parsing logic for proprietary media types.
    """
    class Defaults(Enum):
        JSON = "application/json"
        FORM_URLENCODED = "application/x-www-form-urlencoded"
        MULTIPART_FORM = "multipart/form-data"
        PLAIN_TEXT = "text/plain"

    def __init__(
        self,
        builtin_parsers: Optional[List["PayloadParser.Defaults"]] = None,
        custom_parsers: Optional[Dict[str, Callable[[Request], Awaitable[Any]]]] = None
    ):
        """
        Initializes the parser registry.

        Args:
            builtin_parsers: List of PayloadParser.Defaults to enable.
            custom_parsers: Mapping of mime-type strings to async parsing functions.
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
    async def _parse_json(request: Request):
        return await request.json()

    @staticmethod
    async def _parse_form_urlencoded(request: Request):
        form = await request.form()
        return dict(form)

    @staticmethod
    async def _parse_plain_text(request: Request):
        body_bytes = await request.body()
        return body_bytes.decode('utf-8', errors='replace')

    @staticmethod
    async def _parse_multipart_form(request: Request) -> Dict[str, Any]:
        form: FormData = await request.form()

        form_data = {}
        file_data = []

        for key, value in form.multi_items():
            # Robust Check: If it's a string, it's a form field.
            # Anything else in FormData is an UploadFile-like object.
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
        """
        return self.parsers.get(content_type)


class GAERequestLogger:
    """
    A logger for emitting structured request logs in Google App Engine.

    This logger is designed to work with FastAPI applications deployed on Google App Engine. It logs
    structured data after each request is handled, including the HTTP request method, URL, status,
    user agent, response size, latency, and remote IP address. The log severity is determined by the
    maximum log level recorded during the request.

    Attributes:
        LOG_LEVEL_TO_SEVERITY (Dict[int, str]): Mapping of Python logging levels to Cloud Logging severity levels.
        logger (Logger): The Google Cloud Logger instance to log requests.
        resource (Resource): The Google Cloud resource associated with the logger.
        log_payload (bool): Whether to log the request payload for certain HTTP methods. Defaults to True.
        log_headers (bool): Whether to log the request headers. Defaults to True.
        custom_payload_parsers (Dict[str, Callable], optional): A dictionary mapping content types to custom
            parser functions for logging request payloads. If provided, these will override default parsers.
            Defaults to None.
    """
    LOG_LEVEL_TO_SEVERITY: Dict[int, str] = {
        logging.NOTSET: 'DEFAULT',
        logging.DEBUG: 'DEBUG',
        logging.INFO: 'INFO',
        logging.WARNING: 'WARNING',
        logging.ERROR: 'ERROR',
        logging.CRITICAL: 'CRITICAL',
    }

    def __init__(self, logger: Logger, resource: Resource, log_payload: bool = True, log_headers: bool = True,
                 builtin_payload_parsers: Optional[List[PayloadParser.Defaults]] = None,
                 custom_payload_parsers: Dict[str, Callable] = None) -> None:
        """
        Initialize the GAERequestLogger.

        Args:
            logger (Logger): The Google Cloud Logger instance to log requests.
            resource (Resource): The resource associated with the logger.
            log_payload (bool): Whether to log the request payload for certain HTTP methods. Defaults to True.
            log_headers (bool): Whether to log the request headers. Defaults to True.
            custom_payload_parsers (Dict[str, Callable], optional): A dictionary mapping content types to custom
                parser functions for logging request payloads. If provided, these will override default parsers.
                Defaults to None.
        """
        self.logger = logger
        self.resource = resource
        self.log_payload = log_payload
        self.log_headers = log_headers
        self.payload_parsers = PayloadParser(
            builtin_parsers=builtin_payload_parsers,
            custom_parsers=custom_payload_parsers
        )

    def _log_level_to_severity(self, log_level: int) -> str:
        """
        Convert Python logging level to Cloud Logging severity.

        Args:
            log_level (int): The logging level.

        Returns:
            str: The corresponding Cloud Logging severity.
        """
        return self.LOG_LEVEL_TO_SEVERITY.get(log_level, self.LOG_LEVEL_TO_SEVERITY[logging.NOTSET])

    async def emit_request_log(self, request: Request, response: Response) -> None:
        """
        Log structured data after handling the request and right before returning a response.
        Severity of log is determined based on the maximum log level
        captured in the request state context.

        Args:
            request: The request object.
            response: The response object.
        """
        gae_request_context_data = get_gae_context()
        trace = gae_request_context_data['trace']

        if not trace:
            return

        severity = self._log_level_to_severity(log_level=gae_request_context_data['max_log_level'])

        http_request = {
            'requestMethod': request.method,
            'requestUrl': str(request.url),
            'status': response.status_code,
            'userAgent': request.headers.get('User-Agent'),
            'responseSize': response.headers.get('Content-Length'),
            'latency': f'{(time.time() - gae_request_context_data["start_time"]):.6f}s',
            'remoteIp': request.client.host
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
                logging_payload['request_payload'] = request_payload

        self.logger.log_struct(
            info=logging_payload,
            resource=self.resource,
            trace=f"projects/{self.logger.project}/traces/{trace.split('/', 1)[0]}",
            http_request=http_request,
            severity=severity
        )


class FastAPIGAELoggingMiddleware:
    """
    ASGI Middleware for request-response correlation and automated logging.

    Maintains the GAE_REQUEST_CONTEXT and ensures a structured log
    is emitted even if the application encounters an unhandled exception.

    Note:
        This middleware caches the request body in memory to allow both the
        logger and the application to read the stream. This may impact memory
        usage for very large uploads.

    Attributes:
    app (ASGIApp): The ASGI application instance.
    logger (GAERequestLogger): The logger used to emit structured logs.
    """

    def __init__(self, app: ASGIApp, logger: GAERequestLogger):
        """
        Initialize the middleware.

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

        headers = dict(scope.get("headers", []))
        trace_header = headers.get(b"x-cloud-trace-context", b"").decode("latin-1") or None

        GAE_REQUEST_CONTEXT.set({
            'trace': trace_header,
            'start_time': time.time(),
            'max_log_level': logging.NOTSET
        })

        _receive_cache = await receive()

        async def receive_cache():
            return _receive_cache

        request = Request(scope, receive=receive_cache)
        # Default response in case of an error
        response = Response(status_code=500)

        # Intercept the sent message to get the response status and body
        # for later use
        async def send_spoof_wrapper(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                response.status_code = message["status"]
            elif message["type"] == "http.response.body":
                response.body = message.get("body", b"")
            await send(message)

        try:
            await self.app(scope, receive_cache, send_spoof_wrapper)
        except Exception as e:
            if not isinstance(e, HTTPException):
                logging.exception(e)
            raise e
        finally:
            await self.logger.emit_request_log(request, response)


class FastAPIGAELoggingHandler(CloudLoggingHandler):
    """
    Custom Cloud Logging handler for FastAPI applications deployed on Google App Engine.

    This handler groups logs from the same request lifecycle and propagates the maximum log level
    observed throughout the request. It also integrates with FastAPI by adding middleware that
    handles request and response logging.
    """

    REQUEST_LOGGER_SUFFIX: str = '-request-logger'

    def __init__(
            self,
            app: Starlette,
            client: Client,
            request_logger_name: Optional[str] = None,
            log_payload: bool = True,
            log_headers: bool = True,
            builtin_payload_parsers: Optional[List["PayloadParser.Defaults"]] = None,
            custom_payload_parsers: Dict[str, Callable] = None,
            *args, **kwargs
    ) -> None:
        """
        Initialize the handler.

        Args:
            app (FastAPI | Starlette): The FastAPI or Starlette application instance.
            request_logger_name (Optional[str]): The name of the Cloud Logging logger to use for request logs.
                Defaults to the Google Cloud Project ID with '-request-logger' suffix.
            log_payload (bool): Whether to log the request payload for certain HTTP methods. Defaults to True.
            log_headers (bool): Whether to log the request headers. Defaults to True.
            custom_payload_parsers (Dict[str, Callable], optional): A dictionary mapping content types to custom
                parser functions for logging request payloads. If provided, these will override default parsers.
                Defaults to None.
            *args: Additional arguments to pass to the superclass constructor.
                Any argument you would pass to CloudLoggingHandler.
            **kwargs: Additional keyword arguments to pass to the superclass constructor.
                Any keyword argument you would pass to CloudLoggingHandler.
        """
        super().__init__(client, *args, **kwargs)
        self.app = app
        self.project_id = client.project
        self.app.add_middleware(
            middleware_class=FastAPIGAELoggingMiddleware,
            logger=GAERequestLogger(
                logger=self.client.logger(
                    name=request_logger_name or f"{self.project_id}{self.REQUEST_LOGGER_SUFFIX}",
                    resource=self.resource
                ),
                resource=self.resource,
                log_payload=log_payload,
                log_headers=log_headers,
                builtin_payload_parsers=builtin_payload_parsers,
                custom_payload_parsers=custom_payload_parsers
            )
        )
        self.addFilter(LogInterceptor(project_id=self.project_id))
