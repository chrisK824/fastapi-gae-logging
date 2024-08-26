# fastapi-gae-logging
Custom Cloud Logging handler for FastAPI applications deployed in Google App Engine.
Groups logs coming from the same request lifecycle and propagates the maximum log level throughout the request lifecycle using middleware and context management.

## Install
`pip install fastapi-gae-logging`

## Features:

- **Request Logs Grouping**: Groups logs coming from the same request lifecycle to ease out log analysis using the Google Cloud Log Explorer. Grouping logger name can be customised and it defaults to the Google Cloud Project ID with '-request-logger' as a suffix.
- **Request Maximum Log Level propagation**: Propagates the maximum log level throughout the request lifecycle to ease out log searching based on severity of an issue.

## API
- Custom Cloud Logging Handler to use with official library `google-cloud-logging`: `FastAPIGAELoggingHandler`


## Example

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
    setup_logging(handler=gae_log_handler)


logging.getLogger().setLevel(logging.DEBUG)


@app.get("/info")
def info():
    logging.debug("this is a debug")
    logging.info("this is an info")
    return JSONResponse(
        content={
            "message": "info"
        }
    )


@app.get("/warning")
async def warning():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.warning("this is a warning")
    return JSONResponse(
        content={
            "message": "warning"
        }
    )


@app.get("/error")
def error():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.warning("this is a warning")
    logging.error("this is an error")
    return JSONResponse(
        content={
            "message": "error"
        }
    )


@app.get("/exception")
def exception():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.error("this is an error")
    raise ValueError("This is a value error")


@app.get("/http_exception")
def http_exception():
    logging.debug("this is an debug")
    logging.info("this is an info")
    raise HTTPException(
        status_code=404,
        detail={
            "error": "Resource not found"
        }
    )
```
