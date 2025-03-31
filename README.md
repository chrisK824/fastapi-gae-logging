# fastapi-gae-logging
Custom Cloud Logging handler for FastAPI (or any Starlette based) applications deployed in Google App Engine to ease out logs analysis and monitoring through Google Cloud Log Explorer.

## What problem does this package solve? Why do we need this?
When deploying FastAPI applications on Google App Engine, I encountered several challenges with logging and observability even when using the official package for this purpose, `google-cloud-logging`.

- **Scattered Logs**: Logs generated during a single request lifecycle were scattered across different log entries, making it difficult to trace the entire flow of a request, especially when troubleshooting issues.

- **Log Severity Mismatch**: The severity level of logs was not properly propagated throughout the request lifecycle. This meant that if an error occurred at any point in the request, the earlier logs did not reflect the severity of the final outcome, making it harder to identify problematic requests.

- **Payload Logging Issues**: Capturing and logging request payloads was cumbersome, requiring extra logging in the handlers and extra deployments. This led to incomplete logs, making it harder to reproduce issues or analyze request content.

- **Inconsistent Log Structures**: The default logging setup lacked a consistent structure, which made it challenging to filter, search, and analyze logs in the Google Cloud Log Explorer.

## So what does it do? 
The `fastapi-gae-logging` module addresses these problems by:

- **Grouping Logs by Request**: All logs generated during a request's lifecycle are grouped together, allowing for a complete view of the request flow in the Google Cloud Log Explorer. This makes it much easier to trace and troubleshoot issues.

- **Log Level Propagation**: The maximum log level observed during a request's lifecycle is propagated, ensuring that logs associated with a failed request reflect the appropriate severity. This improves the accuracy and utility of log searches based on severity.

- **Structured Payload Logging**: Request payloads are captured and logged in a structured format, even for non-dictionary JSON payloads. This ensures that all relevant request data is available for analysis, improving the ability to diagnose issues.


## Install
`pip install fastapi-gae-logging`

## Features:

- **Request Logs Grouping**: Groups logs from the same request lifecycle to simplify log analysis using Google Cloud Log Explorer. The logger name for grouping can be customized and defaults to the Google Cloud Project ID with '-request-logger' as a suffix.
- **Request Maximum Log Level Propagation**: Propagates the maximum log level throughout the request lifecycle, making it easier to search logs based on the severity of an issue.
- **Optional incoming request logging**: Opt in/out to log headers and payload of incoming requests into the `jsonPayload` field of the parent log.
- **Optional request headers logging**: Defaults to True. Headers dict lands into field `request_headers` in the `jsonPayload` of parent log.
- **Request Payload Logging**: Defaults to True. Incoming payload parsed lands into field `request_payload` in the `jsonPayload` of parent log. Parsing is based on content type with capability to override. Currenty embedded parsers for:
    - `application/json`
    - `application/x-www-form-urlencoded`
    - `text/plain`

## API

- Initialization

```python
FastAPIGAELoggingHandler(
    app: Starlette,
    request_logger_name: Optional[str] = None,
    log_payload: bool = True,
    log_headers: bool = True,
    custom_payload_parsers: Dict[str, Callable] = None,
    *args, **kwargs
)
```

- Parameters
    - **app** (FastAPI | Starlette): The FastAPI or Starlette application instance.
    - **request_logger_name** (Optional[str], optional): The name of the Cloud Logging logger to use for request logs.
                                                    Defaults to the Google Cloud Project ID with the suffix '-request-logger'.

    - **log_payload** (bool, optional): Whether to log the request payload. If True, the payload for POST, PUT, PATCH, and DELETE requests will be logged. Defaults to True.

    - **log_headers** (bool, optional): Whether to log the request headers. Defaults to True.
    - **custom_payload_parsers**  (Dict[str, Callable], optional): A dictionary mapping content types to custom parser functions for logging request payloads. If provided, these will override default parsers. Defaults to None.

    - ***args**: Additional arguments to pass to the superclass constructor. Any argument you would pass to CloudLoggingHandler.

    - ****kwargs**: Additional keyword arguments to pass to the superclass constructor. Any keyword argument you would pass to  CloudLoggingHandler.


## Example of usage

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
import logging
import os
import traceback

app = FastAPI()

async def custom_payload_parser_plain_text(request: Request):
    try:
        body_bytes = await request.body()
        incoming_payload = body_bytes.decode('utf-8')
        return f"This was the original request payload: {incoming_payload}"
    except Exception as e:
        return f"Failed to read request payload as plain text: {e} | {traceback.format_exc()}"



if os.getenv('GAE_ENV', '').startswith('standard'):
    import google.cloud.logging
    from google.cloud.logging_v2.handlers import setup_logging
    from fastapi_gae_logging import FastAPIGAELoggingHandler

    client = google.cloud.logging.Client()
    # overriding default parsing for payload when content type is 'text/plain'
    gae_log_handler = FastAPIGAELoggingHandler(
        app=app,
        client=client,
        custom_payload_parsers={
            "text/plain": custom_payload_parser_plain_text
        }
    )
    # use the log_payload parameter if you want to opt-out from payload logging
    # gae_log_handler = FastAPIGAELoggingHandler(app=app, client=client, log_payload=False)
    setup_logging(handler=gae_log_handler)

logging.getLogger().setLevel(logging.DEBUG)

@app.get("/info")
def info():
    logging.debug("this is a debug")
    logging.info("this is an info")
    return JSONResponse(
        content={"message": "info"}
    )

@app.get("/warning")
async def warning():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.warning("this is a warning")
    return JSONResponse(
        content={"message": "warning"}
    )

@app.get("/error")
def error():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.warning("this is a warning")
    logging.error("this is an error")
    return JSONResponse(
        content={"message": "error"}
    )

@app.get("/exception")
def exception():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.error("this is an error")
    raise ValueError("This is a value error")

@app.get("/http_exception")
def http_exception():
    logging.debug("this is a debug")
    logging.info("this is an info")
    raise HTTPException(
        status_code=404,
        detail={"error": "Resource not found"}
    )

@app.post("/post_payload")
def post_payload(payload: Any = Body(None)):
    logging.debug("this is an debug")
    logging.info(payload)
    return JSONResponse(content={"mirror_response": payload}, status_code=200)

```

## How it looks in Google Cloud Log Explorer

### Logger selection
![alt text](https://github.com/chrisK824/fastapi-gae-logging/raw/main/logger_selection.jpg)

### Groupped logs with propagated log severity to the parent log

![alt text](https://github.com/chrisK824/fastapi-gae-logging/raw/main/groupped_logs.jpg)

### Grouped logs in request with payload
![alt text](https://github.com/chrisK824/fastapi-gae-logging/raw/main/request_with_payload.jpg)

## Dependencies
This tool is built upon the following packages:

- `starlette`: Starlette is a lightweight ASGI framework/toolkit, which is ideal for building async web services in Python. FastAPI is built on top of Starlette.
- `google-cloud-logging`: Google Cloud Logging API client library for logging and managing logs in Google Cloud Platform.


## Implementation Concept
- **Middleware Integration**: A custom middleware integrates into FastAPI to intercept requests and log data after processing.The custom middleware is added to the FastAPI application during the initialization of the FastAPIGAELoggingHandler.
- **Context Management**: Uses context variables to manage request-specific data and metadata such as request payload, Google Cloud trace ID, start time of the incoming request and the maximum log level observed during the request lifecycle.
- **Log Interception**: A logging filter intercepts log records, injecting trace information and adjusting the maximum log level based on observed log severity.
- **Cloud Logging**: Utilizes Google Cloud Logging to group logs by request and propagate the maximum log level, enhancing observability and troubleshooting.
- **Structured Logging**: Parent log of the request-response lifecycle is structured and sent to Google Cloud Logging with additional context, such as the request method, URL, and user agent after the request has been processed and served.

