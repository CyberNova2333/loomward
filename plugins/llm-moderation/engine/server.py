# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Loopback HTTP server for the out-of-process LoomWard LLM content moderation engine."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import signal
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from .media_sanitizer import probe_optional_decoders
from .router import evaluate_inspection, get_shadow_stats

MAX_BODY_BYTES = 24 * 1024 * 1024
SERVICE_TOKEN = os.environ.pop("LOOMWARD_MODERATION_SERVICE_TOKEN", "") or ""


def is_loopback_host(host: str) -> bool:
    cleaned = (host or "").strip().lower().strip("[]")
    if cleaned == "localhost":
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


class ModerationHTTPServer(ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, address, handler):
        if not is_loopback_host(address[0]):
            raise ValueError("LLM moderation service must bind strictly to a loopback address.")
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)


def _make_handler():
    class ModerationRequestHandler(BaseHTTPRequestHandler):
        server_version = "LoomWardModeration/2.0"

        def log_message(self, format: str, *args: Any) -> None:
            # Never log raw payloads, headers, or credentials to stdout/stderr.
            return

        def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _authorize_post(self) -> bool:
            if not SERVICE_TOKEN:
                return False
            token = self.headers.get("X-LoomWard-Service-Token", "")
            return bool(token) and hmac.compare_digest(token.encode("utf-8"), SERVICE_TOKEN.encode("utf-8"))

        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] == "/api/status":
                resp: Dict[str, Any] = {
                    "status": "ok",
                    "protocolVersion": 2,
                    "decoders": probe_optional_decoders(),
                    "shadowTelemetry": get_shadow_stats(),
                }
                challenge = self.headers.get("X-LoomWard-Challenge", "")
                if challenge and SERVICE_TOKEN and len(challenge) <= 128:
                    resp["token_proof"] = hmac.new(
                        SERVICE_TOKEN.encode("utf-8"),
                        f"status:{challenge}".encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                self._send_json(200, resp)
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path.split("?", 1)[0] != "/api/inspect":
                self._send_json(404, {"error": "not_found"})
                return
            if not self._authorize_post():
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                content_len = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "invalid_content_length"})
                return
            if content_len <= 0 or content_len > MAX_BODY_BYTES:
                self._send_json(413, {"error": "payload_too_large"})
                return
            raw_body = self.rfile.read(content_len)
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid_json"})
                return
            if not isinstance(body, dict) or not isinstance(body.get("request"), dict) or not isinstance(body.get("config"), dict):
                self._send_json(400, {"error": "invalid_inspect_envelope"})
                return

            try:
                result = evaluate_inspection(
                    inspect_request=body["request"],
                    config=body["config"],
                    auth=body.get("auth") if isinstance(body.get("auth"), dict) else None,
                    workspace_roots=body.get("workspaceRoots") if isinstance(body.get("workspaceRoots"), list) else None,
                )
            finally:
                # Explicitly discard transient credential map immediately after inspection.
                if isinstance(body.get("auth"), dict):
                    body["auth"].clear()

            self._send_json(200, result)

    return ModerationRequestHandler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LoomWard Out-of-Process LLM Content Moderation Engine")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback bind host")
    parser.add_argument("--port", type=int, default=0, help="Loopback bind port (0 for ephemeral)")
    args = parser.parse_args(argv)

    if not is_loopback_host(args.host):
        raise SystemExit("Refusing non-loopback bind host.")

    httpd = ModerationHTTPServer((args.host, args.port), _make_handler())
    if hasattr(signal, "SIGTERM"):
        def _handle_sigterm(_signum, _frame):
            threading.Thread(target=httpd.shutdown, daemon=True).start()
        try:
            signal.signal(signal.SIGTERM, _handle_sigterm)
        except (ValueError, OSError):
            pass

    print("LOOMWARD_READY " + json.dumps({"port": httpd.server_port, "host": args.host}, ensure_ascii=False), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
