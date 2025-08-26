import logging
import time
import contextvars
import os
import re
from typing import Optional, Dict, Any, Callable
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Receive, Scope, Send, Message
from starlette.responses import Response
from starlette.requests import Request
from google.cloud.logging_v2.handlers import CloudLoggingHandler
from google.cloud.logging_v2 import Resource, Logger
import traceback


gae_request_context = contextvars.ContextVar('gae_request_context', default={
    'trace': None,
    'start_time': None,
    'max_log_level': logging.NOTSET
})


class LogInterceptor(logging.Filter):
    """
    Logging filter to group logs of a given request and set the maximum log level
    lifecycle for an ASGI app deployed in Google App Engine, using context management and trace.
    for its lifecycle in an ASGI app deployed in Google App Engine, using context management and trace.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records based on the maximum log level set in the request lifecycle.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to allow the log record, False to suppress it.
        """

        gae_request_context_data = gae_request_context.get()
        max_log_level = gae_request_context_data['max_log_level']

        if record.levelno > max_log_level:
            gae_request_context_data['max_log_level'] = record.levelno

        trace = gae_request_context_data['trace']

        if trace:
            split_header = trace.split('/', 1)
            record._trace = f"projects/{os.environ['GOOGLE_CLOUD_PROJECT']}/traces/{split_header[0]}"
            record._span_id = re.findall(r'^\w+', split_header[1])[0]

        return True


class RequestPayloadParser:
    def __init__(self, custom_parsers: Dict[str, Callable] = None):
        self.parsers = {
            "application/json": self._parse_json,
            "application/x-www-form-urlencoded": self._parse_form_urlencoded,
            "text/plain": self._parse_plain_text,
        }

        if custom_parsers:
            self.parsers.update(custom_parsers)

    async def _parse_json(self, request: Request):
        try:
            return await request.json()
        except Exception as e:
            return f"Failed to decode request payload as JSON: {e} | {traceback.format_exc()}"

    async def _parse_form_urlencoded(self, request: Request):
        try:
            form = await request.form()
            return dict(form)
        except Exception as e:
            return f"Failed to parse request form data: {e} | {traceback.format_exc()}"

    async def _parse_plain_text(self, request: Request):
        try:
            body_bytes = await request.body()
            return body_bytes.decode('utf-8')
        except Exception as e:
            return f"Failed to read request payload as plain text: {e} | {traceback.format_exc()}"

    def get_parser(self, content_type: str):
        """
        Returns the parser function for the given content type.
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
        self.payload_parsers = RequestPayloadParser(custom_payload_parsers)

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
        gae_request_context_data = gae_request_context.get()
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
                    request_payload = f"Parser of request payload for content type {content_type} failed: {e} | {traceback.format_exc()}"

            if request_payload:
                logging_payload['request_payload'] = request_payload

        self.logger.log_struct(
            info=logging_payload,
            resource=self.resource,
            trace=f"projects/{os.environ['GOOGLE_CLOUD_PROJECT']}/traces/{trace.split('/', 1)[0]}",
            http_request=http_request,
            severity=severity
        )


class FastAPIGAELoggingMiddleware:
    """
    Middleware to set up request start time and emit logs after request completion.

    This middleware is specifically designed for FastAPI applications deployed on Google App Engine.
    It records the start time of the request and then emits a log after the request is completed,
    containing details about the request and response.

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
        if scope["type"] == "http":

            _receive_cache = await receive()

            async def receive_cache():
                return _receive_cache

            request = Request(scope, receive=receive_cache)

            gae_request_context.set({
                'trace': request.headers.get('X-Cloud-Trace-Context'),
                'start_time': time.time(),
                'max_log_level': logging.NOTSET
            })

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
            request_logger_name: Optional[str] = None,
            log_payload: bool = True,
            log_headers: bool = True,
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
        super().__init__(*args, **kwargs)
        self.app = app
        self.app.add_middleware(
            middleware_class=FastAPIGAELoggingMiddleware,
            logger=GAERequestLogger(
                logger=self.client.logger(
                    name=request_logger_name or f"{os.getenv('GOOGLE_CLOUD_PROJECT')}{self.REQUEST_LOGGER_SUFFIX}",
                    resource=self.resource
                ),
                resource=self.resource,
                log_payload=log_payload,
                log_headers=log_headers,
                custom_payload_parsers=custom_payload_parsers
            )
        )
        self.addFilter(LogInterceptor())
