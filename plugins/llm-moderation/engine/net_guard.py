# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Strict SSRF, TLS >= 1.2, no-redirect, and bounded-response HTTP helper using Python stdlib only."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple


class SecurityPolicyError(ValueError):
    """Raised when an outbound URL or redirect violates SSRF / TLS security boundaries."""


@dataclass
class UpstreamError(RuntimeError):
    """Raised when an upstream moderation model or cloud API fails or rate-limits."""

    message: str
    status_code: Optional[int] = None
    retryable: bool = True

    def __str__(self) -> str:
        return self.message


def _unwrap_mapped_ipv4(ip_obj: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    if ip_obj.ipv4_mapped:
        return ip_obj.ipv4_mapped
    if ip_obj in ipaddress.IPv6Network("64:ff9b::/96") or ip_obj in ipaddress.IPv6Network("64:ff9b:1::/48"):
        return ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)
    if ip_obj in ipaddress.IPv6Network("2002::/16"):
        return ipaddress.IPv4Address((int(ip_obj) >> 80) & 0xFFFFFFFF)
    return None


def _is_loopback_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip_obj.is_loopback:
        return True
    if isinstance(ip_obj, ipaddress.IPv6Address):
        mapped = _unwrap_mapped_ipv4(ip_obj)
        if mapped is not None:
            return mapped.is_loopback
    return False


_ALWAYS_BLOCKED_V4 = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)

_PRIVATE_LAN_V4 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
)


def _is_always_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _ALWAYS_BLOCKED_V4)
    mapped = _unwrap_mapped_ipv4(ip_obj)
    if mapped is not None:
        return _is_always_blocked_ip(mapped)
    if (
        ip_obj in ipaddress.IPv6Network("fe80::/10")
        or ip_obj in ipaddress.IPv6Network("fec0::/10")
        or ip_obj in ipaddress.IPv6Network("ff00::/8")
        or ip_obj in ipaddress.IPv6Network("100::/64")
        or ip_obj in ipaddress.IPv6Network("2001:db8::/32")
    ):
        return True
    return False


def _is_private_lan_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if _is_always_blocked_ip(ip_obj) or _is_loopback_ip(ip_obj):
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _PRIVATE_LAN_V4)
    mapped = _unwrap_mapped_ipv4(ip_obj)
    if mapped is not None:
        return _is_private_lan_ip(mapped)
    return ip_obj in ipaddress.IPv6Network("fc00::/7")


def _is_blocked_public_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return _is_always_blocked_ip(ip_obj) or _is_loopback_ip(ip_obj) or _is_private_lan_ip(ip_obj) or ip_obj.is_reserved


def is_loopback_host(host: str) -> bool:
    cleaned = (host or "").strip().lower().strip("[]")
    if cleaned == "localhost":
        return True
    try:
        return _is_loopback_ip(ipaddress.ip_address(cleaned))
    except ValueError:
        return False


def validate_safe_url(
    raw_url: str,
    *,
    allow_loopback_http: bool = False,
    allow_private_network: bool = False,
    resolve_dns: bool = True,
) -> urllib.parse.ParseResult:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise SecurityPolicyError("Endpoint URL must be a non-empty string.")
    parsed = urllib.parse.urlparse(raw_url.strip())
    if parsed.username or parsed.password:
        raise SecurityPolicyError("Endpoint URL must not embed credentials.")
    host = (parsed.hostname or "").strip().lower().strip("[]")
    if not host:
        raise SecurityPolicyError("Endpoint URL requires a valid hostname.")

    is_loopback_literal = host == "localhost"
    ip_literal: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address] = None
    try:
        ip_literal = ipaddress.ip_address(host)
        is_loopback_literal = _is_loopback_ip(ip_literal)
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        if _is_always_blocked_ip(ip_literal):
            raise SecurityPolicyError(f"Blocked non-public metadata/link-local IP literal: {host}")
        if _is_loopback_ip(ip_literal) and not (allow_loopback_http or allow_private_network):
            raise SecurityPolicyError(f"Blocked loopback IP literal: {host}")
        if _is_private_lan_ip(ip_literal) and not allow_private_network:
            raise SecurityPolicyError(f"Blocked private network IP literal: {host}")
    elif resolve_dns and not is_loopback_literal:
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UpstreamError(f"DNS lookup failed for moderation endpoint: {exc}", retryable=True) from exc
        if not infos:
            raise SecurityPolicyError(f"Hostname resolved to no addresses: {host}")
        for _fam, _type, _proto, _canon, sockaddr in infos:
            resolved_ip = ipaddress.ip_address(sockaddr[0].split("%")[0])
            if _is_always_blocked_ip(resolved_ip):
                raise SecurityPolicyError(f"Blocked resolved metadata/link-local IP for {host}: {resolved_ip}")
            if _is_loopback_ip(resolved_ip) and not (allow_loopback_http or allow_private_network):
                raise SecurityPolicyError(f"Blocked resolved loopback IP for {host}: {resolved_ip}")
            if _is_private_lan_ip(resolved_ip) and not allow_private_network:
                raise SecurityPolicyError(f"Blocked resolved private IP for {host}: {resolved_ip}")
            if parsed.scheme == "http" and not (_is_private_lan_ip(resolved_ip) or (allow_loopback_http and _is_loopback_ip(resolved_ip))):
                raise SecurityPolicyError(f"Plaintext http:// cannot target public resolved IP for {host}: {resolved_ip}")

    if parsed.scheme == "http":
        if is_loopback_literal:
            if not (allow_loopback_http or allow_private_network):
                raise SecurityPolicyError("Plaintext http:// is only allowed for loopback hosts when explicitly enabled.")
        elif ip_literal is not None:
            if not (allow_private_network and _is_private_lan_ip(ip_literal)):
                raise SecurityPolicyError("Plaintext http:// is only allowed for loopback or explicitly authorized private LAN hosts.")
        elif not allow_private_network:
            raise SecurityPolicyError("Plaintext http:// is only allowed for loopback or explicitly authorized private LAN hosts.")
    elif parsed.scheme != "https":
        raise SecurityPolicyError(f"Unsupported URL scheme: {parsed.scheme}")

    return parsed


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SecurityPolicyError(f"Outbound HTTP redirect rejected (HTTP {code}).")


HttpRequester = Callable[..., Tuple[int, Dict[str, str], bytes]]


def safe_http_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout_sec: float = 10.0,
    max_bytes: int = 2 * 1024 * 1024,
    allow_loopback_http: bool = False,
    allow_private_network: bool = False,
    resolve_dns: bool = True,
    http_requester: Optional[HttpRequester] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    validate_safe_url(
        url,
        allow_loopback_http=allow_loopback_http,
        allow_private_network=allow_private_network,
        resolve_dns=resolve_dns,
    )

    if http_requester is not None:
        return http_requester(
            url,
            method=method,
            headers=dict(headers or {}),
            body=body,
            timeout_sec=timeout_sec,
            max_bytes=max_bytes,
        )

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    handlers = [urllib.request.HTTPSHandler(context=ssl_ctx), _NoRedirectHandler()]
    if allow_loopback_http or allow_private_network:
        handlers.append(urllib.request.HTTPHandler())
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(
        url,
        data=body,
        headers=dict(headers or {}),
        method=method.upper(),
    )
    try:
        with opener.open(req, timeout=max(0.5, float(timeout_sec))) as resp:
            status = int(getattr(resp, "status", 200))
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise UpstreamError("Upstream moderation response exceeded maximum size.", status_code=502, retryable=True)
            return status, resp_headers, raw
    except SecurityPolicyError:
        raise
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw_err = exc.read(64 * 1024)
        retryable = status in (408, 429) or status >= 500
        raise UpstreamError(
            f"Upstream moderation HTTP {status}: {raw_err[:200].decode('utf-8', errors='replace')}",
            status_code=status,
            retryable=retryable,
        ) from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
        raise UpstreamError(f"Upstream moderation request error: {exc}", retryable=True) from exc
