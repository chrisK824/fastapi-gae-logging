import argparse
import asyncio
import io
import sys

import httpx

ENDPOINTS = ["/info", "/warning", "/error", "/exception", "/http_exception"]


async def request(client: httpx.AsyncClient, method: str, url: str, label: str, **kwargs):
    try:
        resp = await client.request(method, url, **kwargs)
        print(f"{method:4} {label:20} | Status: {resp.status_code}")
    except Exception as e:
        print(f"{method:4} {label:20} | Failed: {type(e).__name__}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="GAE Project ID")
    args = parser.parse_args()

    base_url = f"https://{args.project}.ew.r.appspot.com"
    
    transport = httpx.AsyncHTTPTransport(retries=3)
    timeout = httpx.Timeout(10.0, read=30.0)

    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
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

        await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)