import logging
import os

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()


async def custom_payload_parser_plain_text(request: Request):
    # Custom parser for text/plain to demonstrate GAE handler extensibility.
    # Needs to return a serializable value to be logged
    body_bytes = await request.body()
    incoming_payload = body_bytes.decode('utf-8')
    return f"Parsed Plain Text: {incoming_payload}"


# Initialize GAE Logging
if os.getenv('GAE_ENV', '').startswith('standard'):
    import google.cloud.logging
    from google.cloud.logging_v2.handlers import setup_logging

    from fastapi_gae_logging import (
        FastAPIGAELoggingHandler,
        GaeLogSizeLimitFilter,
        GaeUrlib3FullPoolFilter,
        PayloadParser,
    )

    client = google.cloud.logging.Client()
    gae_log_handler = FastAPIGAELoggingHandler(
        app=app,
        client=client,
        # Optional - opt in for logging payload and logs; defaults are False
        log_headers=True,
        log_payload=True,
        # Optional - opt in for all built in payload parsers; applicable only if log_payload is set True
        builtin_payload_parsers=[content_type for content_type in PayloadParser.Defaults],
        # Optional - override built in payload parsers or provide more; applicable only if log_payload is set True
        custom_payload_parsers={
            "text/plain": custom_payload_parser_plain_text
        }
    )
    setup_logging(handler=gae_log_handler)
    # Optional - add extra filters for the logger
    gae_log_handler.addFilter(GaeLogSizeLimitFilter())
    gae_log_handler.addFilter(GaeUrlib3FullPoolFilter())


logging.getLogger().setLevel(logging.DEBUG)


@app.get("/info")
def info():
    logging.debug("Step 1: Debugging diagnostic")
    logging.info("Step 2: General information log")
    return JSONResponse(
        content={
            "message": "info"
        }
    )


@app.get("/warning")
async def warning():
    logging.debug("Step 1: Check system state")
    logging.info("Step 2: State is normal")
    logging.warning("Step 3: Resource usage approaching threshold")
    return JSONResponse(
        content={
            "message": "warning"
        }
    )


@app.get("/error")
def error():
    logging.debug("Step 1: Internal check")
    logging.info("Step 2: Transaction started")
    logging.warning("Step 3: Retry attempted")
    logging.error("Step 4: Transaction failed after retries")
    return JSONResponse(
        content={
            "message": "error"
        }
    )


@app.get("/exception")
def exception():
    logging.debug("Step 1: Preparing logic")
    logging.info("Step 2: Executing risky operation")
    logging.error("Step 3: Critical failure detected")
    raise ValueError("Simulated ValueError for GAE grouping demonstration")


@app.get("/http_exception")
def http_exception():
    logging.debug("Step 1: Looking up resource")
    logging.info("Step 2: Resource ID not found in database")
    raise HTTPException(
        status_code=404,
        detail={
            "error": "Resource not found"
        }
    )


@app.post("/post_payload")
async def post_payload(request: Request):
    content_type = request.headers.get("content-type", "")
    logging.debug(f"Handling POST request with Content-Type: {content_type}")

    payload = None

    # 1. Handle JSON
    if "application/json" in content_type:
        try:
            payload = await request.json()
            logging.info(f"Parsed as JSON: {payload}")
        except Exception:
            logging.warning("Failed to parse body as JSON")
            payload = None

    # 2. Handle Form URL-Encoded
    elif "application/x-www-form-urlencoded" in content_type:
        form_data = await request.form()
        payload = dict(form_data)
        logging.info(f"Parsed as Form URL-Encoded: {payload}")

    # 3. Fallback for Plain Text or others
    else:
        body_bytes = await request.body()
        payload = body_bytes.decode("utf-8", errors="replace")
        logging.info(f"Parsed as Raw/Text: {payload}")

    return JSONResponse(
        content={
            "mirror_response": payload,
            "detected_type": str(type(payload)),
            "content_type_received": content_type
        },
        status_code=200
    )


@app.post("/post_form")
async def post_form(description: str = Form(...), file: UploadFile = File(...)):  # noqa: B008
    file_content = await file.read()
    
    payload = {
        "description": description,
        "file_name": file.filename,
        "content_type": file.content_type,
        "file_size": len(file_content),
    }
    
    logging.info(f"Form submission processed: {payload}")
    return JSONResponse(content={"mirror_response": payload}, status_code=200)
