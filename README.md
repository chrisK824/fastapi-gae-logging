# fastapi-gae-logging
Custom Cloud Logging handler for FastAPI applications deployed in Google App Engine to ease out logs analysis and monitoring through Google Cloud Log Explorer.

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
- **Request Payload Logging**:
    - Logs the payload of a request as part of the parent log in request-grouped logs.
    - Assumes the payload is a valid JSON - basically what Python's `json.loads()` can parse - otherwise, it is discarded.
    - Logs the payload as a dictionary using the `google-cloud-logging`'s `log_struct` method. If the payload is not a dictionary, then it is wrapped in a dummy keyword to construct one. The dummy keyword follows the format: `<original_type_of_payload>__payload_wrapper`. For example, if the payload is a list, which still a valid JSON which Python's `json.loads()` will parse just fine, then the payload list will be wrapped in a virtual dictionary under the key `list_payload_wrapper`. The dictionary is logged alongside the parent log in request-grouped logs and ends up in the `jsonPayload` field.


## API

- Initialization

```python
FastAPIGAELoggingHandler(
    app: FastAPI,
    request_logger_name: Optional[str] = None,
    log_payload: bool = True,
    *args, **kwargs
)
```

- Parameters
    - **app** (FastAPI): The FastAPI application instance.
    - **request_logger_name** (Optional[str], optional): The name of the Cloud Logging logger to use for request logs.
                                                    Defaults to the Google Cloud Project ID with the suffix '-request-logger'.

    - **log_payload** (bool, optional): Whether to log the request payload. If True, the payload for POST, PUT, PATCH, and DELETE requests will be logged. Defaults to True.

    - ***args**: Additional arguments to pass to the superclass constructor. Any argument you would pass to CloudLoggingHandler.

    - ****kwargs**: Additional keyword arguments to pass to the superclass constructor. Any keyword argument you would pass to  CloudLoggingHandler.


## Example of usage

```python
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
import logging
import os

app = FastAPI()

if os.getenv('GAE_ENV', '').startswith('standard'):
    import google.cloud.logging
    from google.cloud.logging_v2.handlers import setup_logging
    from fastapi_gae_logging import FastAPIGAELoggingHandler

    client = google.cloud.logging.Client()
    gae_log_handler = FastAPIGAELoggingHandler(app=app, client=client)
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

- `fastapi`: A modern, fast (high-performance), web framework for building APIs with Python 3.7+ based on standard Python type hints.
- `google-cloud-logging`: Google Cloud Logging API client library for logging and managing logs in Google Cloud Platform.


## Implementation Concept
- **Middleware Integration**: A custom middleware integrates into FastAPI to intercept requests and log data after processing.The custom middleware is added to the FastAPI application during the initialization of the FastAPIGAELoggingHandler.
- **Context Management**: Uses context variables to manage request-specific data and metadata such as request payload, Google Cloud trace ID, start time of the incoming request and the maximum log level observed during the request lifecycle.
- **Log Interception**: A logging filter intercepts log records, injecting trace information and adjusting the maximum log level based on observed log severity.
- **Cloud Logging**: Utilizes Google Cloud Logging to group logs by request and propagate the maximum log level, enhancing observability and troubleshooting.
- **Structured Logging**: Parent log of the request-response lifecycle is structured and sent to Google Cloud Logging with additional context, such as the request method, URL, and user agent after the request has been processed and served.

