"""Local-only IOC validation and enrichment helpers."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


ALLOWED_IOC_TYPES = {"ip", "domain", "url", "hash"}
HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class NormalizedIoc:
    ioc_type: str
    value: str


def normalize_ioc(ioc_type: str, value: str) -> NormalizedIoc:
    cleaned_type = ioc_type.strip().lower()
    cleaned_value = value.strip()
    if cleaned_type not in ALLOWED_IOC_TYPES:
        allowed = ", ".join(sorted(ALLOWED_IOC_TYPES))
        raise ValueError(f"Unsupported IOC type '{ioc_type}'. Allowed: {allowed}.")
    if not cleaned_value:
        raise ValueError("IOC value cannot be empty.")

    if cleaned_type == "ip":
        return NormalizedIoc(cleaned_type, str(ipaddress.ip_address(cleaned_value)))
    if cleaned_type == "domain":
        return NormalizedIoc(cleaned_type, normalize_domain(cleaned_value))
    if cleaned_type == "url":
        return NormalizedIoc(cleaned_type, normalize_url(cleaned_value))
    return NormalizedIoc(cleaned_type, normalize_hash(cleaned_value))


def enrich_ioc(ioc_type: str, value: str) -> tuple[NormalizedIoc, dict[str, object]]:
    normalized = normalize_ioc(ioc_type, value)
    if normalized.ioc_type == "ip":
        ip = ipaddress.ip_address(normalized.value)
        return normalized, {
            "version": ip.version,
            "private": ip.is_private,
            "public": ip.is_global,
            "loopback": ip.is_loopback,
            "reserved": ip.is_reserved,
        }
    if normalized.ioc_type == "domain":
        return normalized, {
            "valid": True,
            "punycode": normalized.value,
        }
    if normalized.ioc_type == "url":
        parsed = urlparse(normalized.value)
        return normalized, {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "path": parsed.path,
            "has_query": bool(parsed.query),
        }
    return normalized, {
        "algorithm": hash_algorithm(normalized.value),
        "hex": True,
        "length": len(normalized.value),
    }


def normalize_domain(value: str) -> str:
    if any(character.isspace() for character in value):
        raise ValueError("Domain IOC cannot contain whitespace.")
    domain = value.rstrip(".").lower()
    if not domain or len(domain) > 253 or "." not in domain:
        raise ValueError("Domain IOC must be a fully qualified domain name.")
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain IOC is not valid IDNA.") from exc
    labels = ascii_domain.split(".")
    if any(not label for label in labels):
        raise ValueError("Domain IOC contains an empty label.")
    for label in labels:
        if not DOMAIN_LABEL_RE.fullmatch(label):
            raise ValueError("Domain IOC has invalid label syntax.")
    return ascii_domain


def normalize_url(value: str) -> str:
    if any(character.isspace() for character in value):
        raise ValueError("URL IOC cannot contain whitespace.")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL IOC scheme must be http or https.")
    if not parsed.hostname:
        raise ValueError("URL IOC must include a host.")
    if parsed.username or parsed.password:
        raise ValueError("URL IOC must not include credentials.")
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        normalize_domain(host)
    return value


def normalize_hash(value: str) -> str:
    digest = value.lower()
    if len(digest) not in {32, 40, 64} or not HEX_RE.fullmatch(digest):
        raise ValueError("Hash IOC must be MD5, SHA1, or SHA256 hex.")
    return digest


def hash_algorithm(value: str) -> str:
    return {32: "MD5", 40: "SHA1", 64: "SHA256"}[len(value)]
