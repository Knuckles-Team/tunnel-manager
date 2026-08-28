#!/usr/bin/env python3
import asyncio
import json
import os
import uuid

import httpx

A2A_URL = os.environ.get("A2A_URL", "http://127.0.0.1:9016/a2a/")


def _build_message_payload(query: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "role": "user",
                "parts": [{"kind": "text", "text": query}],
                "messageId": str(uuid.uuid4()),
            }
        },
        "id": 1,
    }


async def _poll_task(client: httpx.AsyncClient, url: str, task_id: str) -> dict | None:
    """Poll tasks/get until the task leaves an in-flight state.

    Returns the final poll response body, or None if polling ended early
    (a transport failure or a JSON-RPC error).
    """
    while True:
        await asyncio.sleep(2)
        poll_payload = {
            "jsonrpc": "2.0",
            "method": "tasks/get",
            "params": {"id": task_id},
            "id": 2,
        }
        poll_resp = await client.post(
            url, json=poll_payload, headers={"Content-Type": "application/json"}
        )
        if poll_resp.status_code != 200:
            print(f"Polling Failed: {poll_resp.status_code}")
            print(f"Polling failed with HTTP {poll_resp.status_code}.")
            return None

        poll_data = poll_resp.json()
        if "result" not in poll_data:
            print("Starting polling error key check...")
            if "error" in poll_data:
                print(
                    f"Polling JSON-RPC error code: {poll_data['error'].get('code', 'unknown')}"
                )
            return None

        state = poll_data["result"]["status"]["state"]
        print(f"Task State: {state}")
        if state not in ["submitted", "running", "working"]:
            print(f"\nTask Finished with state: {state}")
            return poll_data


def _find_last_agent_message(history: list) -> dict | None:
    """Return the last message in history that was not sent by the user."""
    return next((msg for msg in reversed(history) if msg.get("role") != "user"), None)


def _print_agent_message(last_msg: dict | None) -> None:
    """Print a found agent message, or note that none was found."""
    if last_msg is None:
        print("\n--- No Agent Response Found in History ---")
        return
    if "parts" not in last_msg:
        print("Final response received without structured parts.")
        return
    print("\n--- Agent Response ---")
    for part in last_msg["parts"]:
        if "text" in part or "content" in part:
            print("Agent response content omitted.")


def _print_last_agent_response(poll_data: dict) -> None:
    """Print the final non-user message in a finished task's history, if any."""
    result = poll_data["result"]
    if "history" not in result:
        return
    history = result["history"]
    if not history:
        print("\n--- No Agent Response Found in History ---")
        return
    _print_agent_message(_find_last_agent_message(history))


async def _handle_task_submission(client: httpx.AsyncClient, url: str, data: dict) -> None:
    """If the response submitted a task, poll it to completion and report the result."""
    if "result" not in data or "id" not in data["result"]:
        return
    task_id = data["result"]["id"]
    print("\nTask submitted; polling for result...")
    poll_data = await _poll_task(client, url, task_id)
    if poll_data is not None:
        _print_last_agent_response(poll_data)
        print("Validation result received; body omitted.")


async def _submit_query(client: httpx.AsyncClient, url: str, query: str) -> None:
    """Send one JSON-RPC message/send request and handle its response."""
    payload = _build_message_payload(query)
    try:
        print("Trying the configured endpoint with JSON-RPC (message/send)...")
        resp = await client.post(
            url, json=payload, headers={"Content-Type": "application/json"}
        )
        print(f"Status Code: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Error: {resp.status_code}")
            print(f"Response body omitted (HTTP {resp.status_code}).")
            return

        try:
            data = resp.json()
        except json.JSONDecodeError:
            print(f"Response body omitted (HTTP {resp.status_code}).")
            return

        print("JSON response received.")
        await _handle_task_submission(client, url, data)
        if "error" in data:
            print(f"JSON-RPC error code: {data['error'].get('code', 'unknown')}")
    except httpx.RequestError:
        print("Connection failed to {url}")


async def main():
    print("Validating the configured A2A agent...")

    questions = [
        os.environ.get("A2A_VALIDATION_QUERY", "Describe your available capabilities.")
    ]

    async with httpx.AsyncClient(timeout=10000.0) as client:
        for q in questions:
            print("\nSubmitting the configured validation query.")
            print("--- Sending Request ---")
            await _submit_query(client, A2A_URL, q)


if __name__ == "__main__":
    asyncio.run(main())
