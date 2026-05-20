"""Passive public web OSINT source adapters."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from rekos.errors import ExternalToolExecutionError

from .base import AdapterResult, BaseSourceAdapter, SourceRunResult


SOURCE_TIMEOUT_SECONDS = 15
MAX_SOURCE_BYTES = 2 * 1024 * 1024
USER_AGENT = "REKOS passive OSINT source adapter"
DNS_QUERY_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "NS": 2,
    "TXT": 16,
}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s<>'\"]+")


class RdapDomainAdapter(BaseSourceAdapter):
    name = "rdap_domain"
    description = "Fetch public RDAP registration data for a domain over HTTPS."
    supported_target_types = ("domain",)
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        domain = normalize_domain(target)
        raw_output = self.run(case, domain)
        artifact_path = self._write_source_output(case, domain, store, raw_output)
        results = self.parse_results(domain, raw_output)
        store.add_adapter_results(case, results)

        domain_entity = store.ensure_entity(case, "domain", domain, "RDAP domain target")
        source_entity = store.ensure_entity(case, "source", self.name, "source adapter")
        for result in results:
            url_entity = store.ensure_entity(case, "url", result.url, "RDAP referenced URL")
            if url_entity.entity_id != domain_entity.entity_id:
                store.relate_entities(
                    case,
                    domain_entity.entity_id,
                    url_entity.entity_id,
                    "related_to",
                    "low",
                    "RDAP referenced URL",
                )
            if url_entity.entity_id != source_entity.entity_id:
                store.relate_entities(
                    case,
                    source_entity.entity_id,
                    url_entity.entity_id,
                    "produced",
                    result.confidence,
                    "RDAP source produced URL",
                )
        store.add_timeline_event(case, "source.run", f"Ran source {self.name} for {domain}")
        return SourceRunResult(
            source=self.name,
            target=domain,
            raw_output=raw_output,
            results=results,
            artifacts=[artifact_path],
        )

    def run(self, case: str, target: str) -> str:
        domain = normalize_domain(target)
        return fetch_public_text(f"https://rdap.org/domain/{quote(domain)}")

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        domain = normalize_domain(target)
        urls = [_rdap_url(domain), *_extract_urls(_load_json(raw_output))]
        return [
            AdapterResult(
                source=self.name,
                target=domain,
                url=url,
                platform=_platform_from_url(url),
                confidence="high" if url == _rdap_url(domain) else "medium",
                raw_reference=url,
            )
            for url in _dedupe(urls)
        ]


class DnsDomainAdapter(BaseSourceAdapter):
    name = "dns_domain"
    description = "Fetch basic public DNS records for a domain over HTTPS DNS."
    supported_target_types = ("domain",)
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        domain = normalize_domain(target)
        raw_output = self.run(case, domain)
        artifact_path = self._write_source_output(case, domain, store, raw_output)
        results = self.parse_results(domain, raw_output)
        store.add_adapter_results(case, results)

        domain_entity = store.ensure_entity(case, "domain", domain, "DNS domain target")
        source_entity = store.ensure_entity(case, "source", self.name, "source adapter")
        for result in results:
            record_entity = store.ensure_entity(
                case,
                _dns_entity_type(result.platform),
                result.url,
                f"DNS {result.platform.upper()} record",
            )
            if record_entity.entity_id != domain_entity.entity_id:
                store.relate_entities(
                    case,
                    domain_entity.entity_id,
                    record_entity.entity_id,
                    "related_to",
                    result.confidence,
                    f"DNS {result.platform.upper()} record",
                )
            if record_entity.entity_id != source_entity.entity_id:
                store.relate_entities(
                    case,
                    source_entity.entity_id,
                    record_entity.entity_id,
                    "produced",
                    result.confidence,
                    "DNS source produced record",
                )
        store.add_timeline_event(case, "source.run", f"Ran source {self.name} for {domain}")
        return SourceRunResult(
            source=self.name,
            target=domain,
            raw_output=raw_output,
            results=results,
            artifacts=[artifact_path],
        )

    def run(self, case: str, target: str) -> str:
        domain = normalize_domain(target)
        queries: list[dict[str, Any]] = []
        errors: list[str] = []
        for record_type in DNS_QUERY_TYPES:
            query = urlencode({"name": domain, "type": record_type})
            try:
                response = _load_json(fetch_public_text(f"https://dns.google/resolve?{query}"))
                queries.append({"type": record_type, "response": response})
            except ExternalToolExecutionError as exc:
                error = str(exc)
                errors.append(f"{record_type}: {error}")
                queries.append({"type": record_type, "error": error})
        if errors and len(errors) == len(DNS_QUERY_TYPES):
            raise ExternalToolExecutionError("; ".join(errors))
        return json.dumps(
            {
                "source": self.name,
                "target": domain,
                "queries": queries,
            },
            indent=2,
            sort_keys=True,
        )

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        domain = normalize_domain(target)
        parsed = _load_json(raw_output)
        queries = parsed.get("queries", []) if isinstance(parsed, dict) else []
        results: list[AdapterResult] = []
        seen: set[tuple[str, str]] = set()
        for query in queries:
            if not isinstance(query, dict):
                continue
            record_type = str(query.get("type") or "").upper()
            response = query.get("response")
            if record_type not in DNS_QUERY_TYPES or not isinstance(response, dict):
                continue
            answers = response.get("Answer", [])
            if not isinstance(answers, list):
                continue
            for answer in answers:
                if not isinstance(answer, dict):
                    continue
                if answer.get("type") != DNS_QUERY_TYPES[record_type]:
                    continue
                value = _normalize_dns_value(record_type, str(answer.get("data") or ""))
                if not value or (record_type, value) in seen:
                    continue
                seen.add((record_type, value))
                raw_reference = f"{record_type} {domain} -> {value}"
                results.append(
                    AdapterResult(
                        source=self.name,
                        target=domain,
                        url=value,
                        platform=record_type.lower(),
                        confidence="high" if record_type in {"A", "AAAA", "MX", "NS"} else "medium",
                        raw_reference=raw_reference,
                    )
                )
        return results


class CrtshDomainAdapter(BaseSourceAdapter):
    name = "crtsh_domain"
    description = "Query crt.sh public certificate transparency results for a domain."
    supported_target_types = ("domain",)
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        domain = normalize_domain(target)
        raw_output = self.run(case, domain)
        artifact_path = self._write_source_output(case, domain, store, raw_output)
        results = self.parse_results(domain, raw_output)
        store.add_adapter_results(case, results)

        root = store.ensure_entity(case, "domain", domain, "crt.sh domain target")
        for result in results:
            subdomain = result.raw_reference
            subdomain_entity = store.ensure_entity(
                case,
                "domain",
                subdomain,
                "crt.sh discovered domain",
            )
            if subdomain_entity.entity_id != root.entity_id:
                store.relate_entities(
                    case,
                    subdomain_entity.entity_id,
                    root.entity_id,
                    "extracted_from",
                    "medium",
                    "crt.sh certificate transparency result",
                )
        store.add_timeline_event(case, "source.run", f"Ran source {self.name} for {domain}")
        return SourceRunResult(
            source=self.name,
            target=domain,
            raw_output=raw_output,
            results=results,
            artifacts=[artifact_path],
        )

    def run(self, case: str, target: str) -> str:
        domain = normalize_domain(target)
        query = urlencode({"q": f"%.{domain}", "output": "json"})
        return fetch_public_text(f"https://crt.sh/?{query}")

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        domain = normalize_domain(target)
        subdomains = _extract_crtsh_domains(domain, _load_json(raw_output))
        return [
            AdapterResult(
                source=self.name,
                target=domain,
                url=f"https://{subdomain}",
                platform="certificate-transparency",
                confidence="medium",
                raw_reference=subdomain,
            )
            for subdomain in subdomains
        ]


class WaybackUrlAdapter(BaseSourceAdapter):
    name = "wayback_url"
    description = "Query public Wayback CDX data for a URL or domain."
    supported_target_types = ("url", "domain")
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        normalized_target = normalize_url_or_domain(target)
        raw_output = self.run(case, normalized_target)
        artifact_path = self._write_source_output(case, normalized_target, store, raw_output)
        results = self.parse_results(normalized_target, raw_output)
        store.add_adapter_results(case, results)

        root_type = "url" if _is_http_url(normalized_target) else "domain"
        root = store.ensure_entity(case, root_type, normalized_target, "Wayback source target")
        for result in results:
            archive_entity = store.ensure_entity(case, "url", result.url, "Wayback archived URL")
            if archive_entity.entity_id != root.entity_id:
                store.relate_entities(
                    case,
                    archive_entity.entity_id,
                    root.entity_id,
                    "extracted_from",
                    "medium",
                    "Wayback CDX result",
                )
        store.add_timeline_event(
            case,
            "source.run",
            f"Ran source {self.name} for {normalized_target}",
        )
        return SourceRunResult(
            source=self.name,
            target=normalized_target,
            raw_output=raw_output,
            results=results,
            artifacts=[artifact_path],
        )

    def run(self, case: str, target: str) -> str:
        normalized_target = normalize_url_or_domain(target)
        query_target = normalized_target if _is_http_url(normalized_target) else f"{normalized_target}/*"
        query = urlencode(
            {
                "url": query_target,
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": "20",
            }
        )
        return fetch_public_text(f"https://web.archive.org/cdx?{query}")

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        normalized_target = normalize_url_or_domain(target)
        archive_urls = _extract_wayback_urls(_load_json(raw_output))
        return [
            AdapterResult(
                source=self.name,
                target=normalized_target,
                url=url,
                platform="wayback",
                confidence="medium",
                raw_reference=url,
            )
            for url in archive_urls
        ]


def fetch_public_text(url: str) -> str:
    request = Request(
        url,
        headers={"User-Agent": USER_AGENT},
        method="GET",
    )
    try:
        with urlopen(request, timeout=SOURCE_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_SOURCE_BYTES)
            headers = dict(response.headers.items())
    except HTTPError as exc:
        details = exc.reason or exc.code
        raise ExternalToolExecutionError(f"HTTP request failed for {url}: {details}") from exc
    except (OSError, TimeoutError, URLError) as exc:
        raise ExternalToolExecutionError(f"HTTP request failed for {url}: {exc}") from exc
    return body.decode(_charset(headers), errors="replace")


def normalize_domain(target: str) -> str:
    cleaned = target.strip().lower().rstrip(".")
    if not cleaned:
        raise ValueError("Domain target cannot be empty.")
    parsed = urlparse(cleaned)
    if parsed.scheme or "/" in cleaned or "@" in cleaned:
        raise ValueError("Domain target must be a bare public domain.")
    try:
        cleaned = cleaned.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain target is not valid IDNA.") from exc
    if not DOMAIN_RE.fullmatch(cleaned):
        raise ValueError("Domain target is not a valid public domain.")
    return cleaned


def normalize_url_or_domain(target: str) -> str:
    cleaned = target.strip()
    if _is_http_url(cleaned):
        parsed = urlparse(cleaned)
        if not parsed.hostname:
            raise ValueError("URL target must include a host.")
        if parsed.username or parsed.password:
            raise ValueError("URL target must not include credentials.")
        return cleaned
    return normalize_domain(cleaned)


def _is_http_url(value: str) -> bool:
    return urlparse(value).scheme in {"http", "https"}


def _load_json(raw_output: str) -> Any:
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        return raw_output


def _extract_urls(value: Any) -> list[str]:
    urls: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            urls.extend(_extract_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.extend(_extract_urls(item))
    elif isinstance(value, str):
        urls.extend(match.group(0).rstrip(").,];") for match in URL_RE.finditer(value))
    return _dedupe(urls)


def _extract_crtsh_domains(domain: str, value: Any) -> list[str]:
    candidates: list[str] = []
    rows = value if isinstance(value, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            raw_value = row.get(field)
            if not isinstance(raw_value, str):
                continue
            for item in raw_value.splitlines():
                candidate = item.strip().lower().lstrip("*.").rstrip(".")
                if candidate == domain or candidate.endswith(f".{domain}"):
                    try:
                        candidates.append(normalize_domain(candidate))
                    except ValueError:
                        continue
    return _dedupe(candidates)


def _extract_wayback_urls(value: Any) -> list[str]:
    rows = value if isinstance(value, list) else []
    if rows and rows[0] == ["timestamp", "original", "statuscode", "mimetype"]:
        rows = rows[1:]
    archive_urls: list[str] = []
    for row in rows:
        timestamp = ""
        original = ""
        if isinstance(row, list) and len(row) >= 2:
            timestamp = str(row[0])
            original = str(row[1])
        elif isinstance(row, dict):
            timestamp = str(row.get("timestamp", ""))
            original = str(row.get("original", ""))
        if not timestamp or not _is_http_url(original):
            continue
        archive_urls.append(f"https://web.archive.org/web/{timestamp}/{original}")
    return _dedupe(archive_urls)


def _dns_entity_type(record_type: str) -> str:
    normalized = record_type.strip().lower()
    if normalized in {"a", "aaaa"}:
        return "ip"
    if normalized == "ns":
        return "nameserver"
    if normalized == "mx":
        return "mx"
    if normalized == "txt":
        return "txt_record"
    return "note"


def _normalize_dns_value(record_type: str, value: str) -> str:
    cleaned = value.strip()
    if record_type == "MX":
        parts = cleaned.split(maxsplit=1)
        if len(parts) == 2 and parts[0].isdigit():
            cleaned = parts[1]
    if record_type in {"MX", "NS"}:
        cleaned = cleaned.rstrip(".")
    if record_type == "TXT":
        cleaned = cleaned.strip('"')
    return cleaned


def _rdap_url(domain: str) -> str:
    return f"https://rdap.org/domain/{quote(domain)}"


def _platform_from_url(url: str) -> str:
    host = urlparse(url).hostname or ""
    if not host:
        return "unknown"
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return host


def _charset(headers: dict[str, str]) -> str:
    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    for part in content_type.split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            return value
    return "utf-8"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
