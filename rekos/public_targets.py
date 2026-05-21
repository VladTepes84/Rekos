"""Validation helpers for passive public OSINT targets."""

from __future__ import annotations

import ipaddress
from urllib.parse import urldefrag, urlparse


BLOCKED_METADATA_IP = ipaddress.ip_address("169.254.169.254")


def normalize_public_http_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty.")
    cleaned, _fragment = urldefrag(cleaned)
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https.")
    if not parsed.hostname:
        raise ValueError("URL must include a host.")
    if parsed.username or parsed.password:
        raise ValueError("URL must not include credentials.")
    validate_public_host(parsed.hostname)
    return cleaned


def validate_public_host(host: str) -> None:
    cleaned = host.strip().lower().rstrip(".")
    if not cleaned:
        raise ValueError("Public target host cannot be empty.")
    if (
        cleaned == "localhost"
        or cleaned.endswith(".localhost")
        or cleaned == "localhost.localdomain"
        or cleaned.endswith(".localhost.localdomain")
    ):
        raise ValueError("Public target must not be localhost.")
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return
    if _is_blocked_ip(ip):
        raise ValueError("Public target must not be an internal, reserved, or local IP address.")


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip == BLOCKED_METADATA_IP
        or ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )
