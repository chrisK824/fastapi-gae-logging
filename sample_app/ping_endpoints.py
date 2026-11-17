import argparse
import asyncio
import io
import sys
from secrets import randbelow, token_hex

import httpx2

from fastapi_gae_logging.fastapi_gae_logging import TraceContext, extract_trace_context

ENDPOINTS = ["/info", "/warning", "/error", "/exception", "/http_exception"]


def new_trace_id() -> str:
    while True:
        value = token_hex(16)
        if value != "0" * 32:  # all zeros is invalid
            return value


def new_span_hex() -> str:
    while True:
        value = token_hex(8)
        if value != "0" * 16:
            return value


def new_span_decimal() -> str:
    # legacy header: decimal, 0 < span < 2**64
    return str(randbelow(2 ** 64 - 1) + 1)


async def request(client: httpx2.AsyncClient, method: str, url: str, label: str, **kwargs):
    headers = kwargs.get("headers", {})

    trace_passed = ""
    
    if headers:
        asgi_headers = {k.lower().encode("latin-1"): v.encode("latin-1") for k, v in headers.items()}
        trace_context: TraceContext = extract_trace_context(asgi_headers)
        if trace_context.trace_id:
            trace_passed = f"| trace={trace_context.trace_id}"

    try:
        resp = await client.request(method, url, **kwargs)
        print(f"{method:4} {label:20} | Status: {resp.status_code} {trace_passed}")
    except Exception as e:
        print(f"{method:4} {label:20} | Failed: {type(e).__name__} {trace_passed}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="GAE Project ID")
    args = parser.parse_args()

    base_url = f"https://{args.project}.ew.r.appspot.com"
    
    transport = httpx2.AsyncHTTPTransport(retries=3)
    timeout = httpx2.Timeout(10.0, read=30.0)

    async with httpx2.AsyncClient(transport=transport, timeout=timeout) as client:
        tasks = []

        # 1. GET Endpoints
        for path in ENDPOINTS:
            tasks.append(request(client, "GET", f"{base_url}{path}", path))

        # 2. JSON (application/json)
        tasks.append(request(
            client, "POST", f"{base_url}/post_payload",
            "JSON Payload", json={"test": "json_value"},
            headers={"Content-Type": "application/json"}
        ))

        # 3. Plain Text (text/plain)
        tasks.append(request(
            client, "POST", f"{base_url}/post_payload",
            "Text Payload", content="Standard plain text",
            headers={"Content-Type": "text/plain"}
        ))

        # 4. Form URL-Encoded (application/x-www-form-urlencoded)
        tasks.append(request(
            client, "POST", f"{base_url}/post_payload",
            "Form URL-Encoded", data={"key1": "val1", "key2": "val2"},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        ))

        # 5. Multipart Form (multipart/form-data)
        file_data = {"file": ("test.txt", io.BytesIO(b"Multipart content"), "text/plain")}
        tasks.append(request(
            client, "POST", f"{base_url}/post_form",
            "Multipart Form", data={"description": "GAE Test"}, files=file_data
        ))

        # 6. Huge JSON
        tasks.append(request(
            client, "POST", f"{base_url}/post_payload",
            "Too large Payload", json={"test": "abcdefghij" * (256 * 1024 // 10)},
            headers={"Content-Type": "application/json"}
        ))

        # 7. calls with traceparent header
        traceparent = f"00-{new_trace_id()}-{new_span_hex()}-01"
        for path in ENDPOINTS:
            tasks.append(
                request(client, "GET", f"{base_url}{path}", path, headers={"traceparent": traceparent})
            )

        # 8. calls with x-cloud-trace-context header
        x_cloud_trace_context = f"{new_trace_id()}/{new_span_decimal()};o=1"
        for path in ENDPOINTS:
            tasks.append(
                request(client, "GET", f"{base_url}{path}", path, headers={"x-cloud-trace-context": x_cloud_trace_context})
            )

        await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
