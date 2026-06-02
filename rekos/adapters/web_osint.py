"""Passive public web OSINT source adapters."""

from __future__ import annotations

import json
import re
import socket
import ssl
from hashlib import md5
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from rekos.errors import ExternalToolExecutionError
from rekos.public_targets import normalize_public_http_url, validate_public_host

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
    "CNAME": 5,
}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63}$", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\"]+")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
PROVIDER_HINTS = {
    "microsoft 365": ("spf.protection.outlook.com", "ms=", "microsoft"),
    "google": ("_spf.google.com", "google-site-verification", "google.com"),
    "atlassian": ("atlassian-domain-verification", "atlassian"),
    "brevo": ("brevo", "sendinblue"),
    "esva": ("esvacloud", "esva"),
}


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
        attempts = _rdap_candidate_urls(domain)
        errors: list[str] = []
        for url in attempts:
            try:
                response = fetch_public_text(url)
                return json.dumps(
                    {
                        "source": self.name,
                        "target": domain,
                        "endpoint": url,
                        "response": _load_json(response),
                    },
                    indent=2,
                    sort_keys=True,
                )
            except ExternalToolExecutionError as exc:
                errors.append(f"{url}: {exc}")
        for url in _rdap_bootstrap_urls(domain):
            if url in attempts:
                continue
            try:
                response = fetch_public_text(url)
                return json.dumps(
                    {
                        "source": self.name,
                        "target": domain,
                        "endpoint": url,
                        "response": _load_json(response),
                    },
                    indent=2,
                    sort_keys=True,
                )
            except ExternalToolExecutionError as exc:
                errors.append(f"{url}: {exc}")
        if domain.endswith(".it"):
            whois_endpoint = f"whois://whois.nic.it/domain/{domain}"
            try:
                response = _whois_lookup(domain, "whois.nic.it")
                return json.dumps(
                    {
                        "source": self.name,
                        "target": domain,
                        "endpoint": whois_endpoint,
                        "response": response,
                    },
                    indent=2,
                    sort_keys=True,
                )
            except ExternalToolExecutionError as exc:
                errors.append(f"{whois_endpoint}: {exc}")
        raise ExternalToolExecutionError(f"RDAP lookup failed for {domain}: {'; '.join(errors)}")

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        domain = normalize_domain(target)
        parsed = _load_json(raw_output)
        endpoint = _rdap_url(domain)
        response: Any = parsed
        if isinstance(parsed, dict) and parsed.get("source") == self.name:
            endpoint = str(parsed.get("endpoint") or endpoint)
            response = parsed.get("response")
        urls = [endpoint, *_extract_urls(response)]
        return [
            AdapterResult(
                source=self.name,
                target=domain,
                url=url,
                platform=_platform_from_url(url),
                confidence="high" if url == endpoint else "medium",
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
                if record_type == "TXT":
                    results.extend(_txt_enrichment_results(domain, value))
        return results


class EmailPassiveAdapter(BaseSourceAdapter):
    name = "email_passive"
    description = "Extract email domain signals with passive DNS and local metadata."
    supported_target_types = ("email",)
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        email = normalize_email(target)
        raw_output = self.run(case, email)
        artifact_path = self._write_source_output(case, email, store, raw_output)
        results = self.parse_results(email, raw_output)
        store.add_adapter_results(case, results)

        local_part, domain = email.split("@", 1)
        email_entity = store.ensure_entity(case, "email", email, "Email investigation target")
        domain_entity = store.ensure_entity(case, "domain", domain, "Domain extracted from email")
        source_entity = store.ensure_entity(case, "source", self.name, "source adapter")
        store.relate_entities(
            case,
            email_entity.entity_id,
            domain_entity.entity_id,
            "related_to",
            "high",
            "Domain extracted from email address",
        )
        for result in results:
            if result.platform == "gravatar_hash":
                continue
            entity_type = _email_entity_type(result.platform)
            if result.platform == "email_target":
                entity = email_entity
            elif result.platform == "email_domain":
                entity = domain_entity
            else:
                entity = store.ensure_entity(
                    case,
                    entity_type,
                    result.url,
                    f"Email passive {result.platform} observation",
                )
            if entity.entity_id != domain_entity.entity_id and result.platform not in {"email_target", "gravatar_hash"}:
                store.relate_entities(
                    case,
                    domain_entity.entity_id,
                    entity.entity_id,
                    "related_to",
                    result.confidence,
                    f"Email domain {result.platform} observation",
                )
            if entity.entity_id != source_entity.entity_id:
                store.relate_entities(
                    case,
                    source_entity.entity_id,
                    entity.entity_id,
                    "produced",
                    result.confidence,
                    "Email passive source produced observation",
                )
        store.add_timeline_event(case, "source.run", f"Ran source {self.name} for {email}")
        store.add_timeline_event(case, "investigation.email", f"Investigated email domain for {local_part}@{domain}")
        return SourceRunResult(
            source=self.name,
            target=email,
            raw_output=raw_output,
            results=results,
            artifacts=[artifact_path],
        )

    def run(self, case: str, target: str) -> str:
        email = normalize_email(target)
        local_part, domain = email.split("@", 1)
        queries: list[dict[str, Any]] = []
        for query_name, record_type in ((domain, "MX"), (domain, "TXT"), (f"_dmarc.{domain}", "TXT")):
            query = urlencode({"name": query_name, "type": record_type})
            try:
                response = _load_json(fetch_public_text(f"https://dns.google/resolve?{query}"))
                queries.append({"name": query_name, "type": record_type, "response": response})
            except ExternalToolExecutionError as exc:
                queries.append({"name": query_name, "type": record_type, "error": str(exc)})
        return json.dumps(
            {
                "source": self.name,
                "target": email,
                "local_part": local_part,
                "domain": domain,
                "gravatar_md5": md5(email.encode("utf-8"), usedforsecurity=False).hexdigest(),
                "queries": queries,
            },
            indent=2,
            sort_keys=True,
        )

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        email = normalize_email(target)
        parsed = _load_json(raw_output)
        if not isinstance(parsed, dict):
            return []
        domain = normalize_domain(str(parsed.get("domain") or email.split("@", 1)[1]))
        gravatar_hash = str(parsed.get("gravatar_md5") or "")
        results = [
            AdapterResult(
                source=self.name,
                target=email,
                url=email,
                platform="email_target",
                confidence="high",
                raw_reference=f"Email target {email}",
            ),
            AdapterResult(
                source=self.name,
                target=email,
                url=domain,
                platform="email_domain",
                confidence="high",
                raw_reference=f"Email domain {domain}",
            ),
        ]
        if re.fullmatch(r"[a-f0-9]{32}", gravatar_hash):
            results.append(
                AdapterResult(
                    source=self.name,
                    target=email,
                    url=f"Gravatar MD5 {email}: {gravatar_hash}",
                    platform="gravatar_hash",
                    confidence="low",
                    raw_reference=f"Local Gravatar MD5 hash for {email}: {gravatar_hash}",
                )
            )

        seen: set[tuple[str, str]] = set()
        provider_evidence: dict[str, list[str]] = {}
        queries = parsed.get("queries", [])
        if not isinstance(queries, list):
            return results
        for query in queries:
            if not isinstance(query, dict):
                continue
            query_name = str(query.get("name") or "")
            record_type = str(query.get("type") or "").upper()
            response = query.get("response")
            if record_type not in {"MX", "TXT"} or not isinstance(response, dict):
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
                if not value or (query_name, record_type, value) in seen:
                    continue
                seen.add((query_name, record_type, value))
                if record_type == "MX":
                    results.append(
                        AdapterResult(
                            source=self.name,
                            target=email,
                            url=value,
                            platform="mx",
                            confidence="high",
                            raw_reference=f"MX {domain} -> {value}",
                        )
                    )
                    _record_provider_evidence(provider_evidence, value)
                    continue
                lowered = value.lower()
                if query_name.lower().startswith("_dmarc.") and "v=dmarc1" in lowered:
                    results.append(
                        AdapterResult(
                            source=self.name,
                            target=email,
                            url=f"DMARC {domain}: {_dmarc_summary(value)}",
                            platform="dmarc",
                            confidence="medium",
                            raw_reference=f"DMARC {query_name} -> {value}",
                        )
                    )
                    continue
                if query_name.lower() == domain and lowered.startswith("v=spf1"):
                    results.append(
                        AdapterResult(
                            source=self.name,
                            target=email,
                            url=f"SPF {domain}: {_spf_summary(value)}",
                            platform="spf",
                            confidence="medium",
                            raw_reference=f"SPF {domain} -> {value}",
                        )
                    )
                    _record_provider_evidence(provider_evidence, value)
        results.extend(_provider_hint_results(self.name, email, provider_evidence))
        return results


class WebDomainAdapter(BaseSourceAdapter):
    name = "web_domain"
    description = "Probe public HTTP/HTTPS endpoints and TLS certificate metadata for a domain."
    supported_target_types = ("domain",)
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        domain = normalize_domain(target)
        raw_output = self.run(case, domain)
        artifact_path = self._write_source_output(case, domain, store, raw_output)
        results = self.parse_results(domain, raw_output)
        store.add_adapter_results(case, results)

        domain_entity = store.ensure_entity(case, "domain", domain, "Web domain target")
        source_entity = store.ensure_entity(case, "source", self.name, "source adapter")
        for result in results:
            entity_type = _web_entity_type(result.platform)
            entity = store.ensure_entity(
                case,
                entity_type,
                result.url,
                f"Web domain {result.platform} observation",
            )
            if entity.entity_id != domain_entity.entity_id:
                store.relate_entities(
                    case,
                    domain_entity.entity_id,
                    entity.entity_id,
                    "related_to",
                    result.confidence,
                    f"Web domain {result.platform} observation",
                )
            if entity.entity_id != source_entity.entity_id:
                store.relate_entities(
                    case,
                    source_entity.entity_id,
                    entity.entity_id,
                    "produced",
                    result.confidence,
                    "Web source produced observation",
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
        probes = [_probe_http_endpoint(f"https://{domain}"), _probe_http_endpoint(f"http://{domain}")]
        return json.dumps(
            {
                "source": self.name,
                "target": domain,
                "probes": probes,
                "tls": _tls_certificate_summary(domain),
            },
            indent=2,
            sort_keys=True,
        )

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        domain = normalize_domain(target)
        parsed = _load_json(raw_output)
        if not isinstance(parsed, dict):
            return []
        results: list[AdapterResult] = []
        for probe in parsed.get("probes", []):
            if not isinstance(probe, dict) or probe.get("error"):
                continue
            requested_url = str(probe.get("url") or "")
            final_url = str(probe.get("final_url") or requested_url)
            status = probe.get("status")
            if final_url:
                parts = [f"status={status}"]
                title = str(probe.get("title") or "").strip()
                server = str(probe.get("server") or "").strip()
                if title:
                    parts.append(f"title={title}")
                if server:
                    parts.append(f"server={server}")
                results.append(
                    AdapterResult(
                        source=self.name,
                        target=domain,
                        url=f"{requested_url} -> {final_url} ({', '.join(parts)})",
                        platform="web_endpoint",
                        confidence="medium",
                        raw_reference=json.dumps(probe, sort_keys=True),
                    )
                )
            if requested_url and final_url and requested_url.rstrip("/") != final_url.rstrip("/"):
                results.append(
                    AdapterResult(
                        source=self.name,
                        target=domain,
                        url=f"{requested_url} -> {final_url}",
                        platform="http_redirect",
                        confidence="medium",
                        raw_reference=json.dumps(probe, sort_keys=True),
                    )
                )
        tls = parsed.get("tls")
        if isinstance(tls, dict) and not tls.get("error"):
            summary = _format_tls_result(domain, tls)
            results.append(
                AdapterResult(
                    source=self.name,
                    target=domain,
                    url=summary,
                    platform="tls_certificate",
                    confidence="medium",
                    raw_reference=json.dumps(tls, sort_keys=True),
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


def _fetch_public_bytes(url: str) -> tuple[int, str, dict[str, str], bytes]:
    request = Request(
        url,
        headers={"User-Agent": USER_AGENT},
        method="GET",
    )
    try:
        with urlopen(request, timeout=SOURCE_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_SOURCE_BYTES)
            headers = dict(response.headers.items())
            status = int(getattr(response, "status", 0) or getattr(response, "getcode", lambda: 0)())
            final_url = str(getattr(response, "geturl", lambda: url)() or url)
    except HTTPError as exc:
        body = exc.read(MAX_SOURCE_BYTES)
        headers = dict(exc.headers.items()) if exc.headers else {}
        return int(exc.code), str(exc.geturl() or url), headers, body
    return status, final_url, headers, body


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
    validate_public_host(cleaned)
    if not DOMAIN_RE.fullmatch(cleaned):
        raise ValueError("Domain target is not a valid public domain.")
    return cleaned


def normalize_url_or_domain(target: str) -> str:
    cleaned = target.strip()
    if _is_http_url(cleaned):
        return normalize_public_http_url(cleaned)
    return normalize_domain(cleaned)


def _is_http_url(value: str) -> bool:
    return urlparse(value).scheme in {"http", "https"}


def _rdap_candidate_urls(domain: str) -> list[str]:
    primary = _rdap_url(domain)
    candidates = [primary]
    if domain.endswith(".it"):
        candidates.append(f"https://rdap.nic.it/domain/{quote(domain)}")
    return _dedupe(candidates)


def _rdap_bootstrap_urls(domain: str) -> list[str]:
    tld = domain.rsplit(".", 1)[-1]
    try:
        bootstrap = _load_json(fetch_public_text("https://data.iana.org/rdap/dns.json"))
    except ExternalToolExecutionError:
        return []
    services = bootstrap.get("services", []) if isinstance(bootstrap, dict) else []
    candidates: list[str] = []
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        tlds, urls = service
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        if tld not in {str(item).lower().lstrip(".") for item in tlds}:
            continue
        for base_url in urls:
            if isinstance(base_url, str) and base_url.startswith("https://"):
                candidates.append(f"{base_url.rstrip('/')}/domain/{quote(domain)}")
    return candidates


def _probe_http_endpoint(url: str) -> dict[str, Any]:
    try:
        status, final_url, headers, body = _fetch_public_bytes(url)
    except (OSError, TimeoutError, URLError, ExternalToolExecutionError) as exc:
        return {"url": url, "error": str(exc)}
    text = body.decode(_charset(headers), errors="replace")
    return {
        "url": url,
        "status": status,
        "final_url": final_url,
        "title": _extract_title(text),
        "server": _header_value(headers, "server"),
        "content_type": _header_value(headers, "content-type"),
        "headers": _selected_headers(headers),
    }


def _tls_certificate_summary(domain: str) -> dict[str, str]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=SOURCE_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return {"error": str(exc)}
    return {
        "subject": _certificate_name(cert.get("subject", ())),
        "issuer": _certificate_name(cert.get("issuer", ())),
        "not_before": str(cert.get("notBefore", "")),
        "not_after": str(cert.get("notAfter", "")),
    }


def _whois_lookup(domain: str, server: str) -> str:
    try:
        with socket.create_connection((server, 43), timeout=SOURCE_TIMEOUT_SECONDS) as sock:
            sock.sendall(f"{domain}\r\n".encode("ascii"))
            chunks: list[bytes] = []
            total = 0
            while total < MAX_SOURCE_BYTES:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
    except (OSError, TimeoutError) as exc:
        raise ExternalToolExecutionError(f"WHOIS lookup failed for {domain}: {exc}") from exc
    return b"".join(chunks).decode("utf-8", errors="replace")


def _format_tls_result(domain: str, tls: dict[str, Any]) -> str:
    subject = str(tls.get("subject") or domain)
    issuer = str(tls.get("issuer") or "unknown issuer")
    not_after = str(tls.get("not_after") or "unknown expiry")
    return f"TLS {domain}: subject={subject}; issuer={issuer}; not_after={not_after}"


def _certificate_name(value: Any) -> str:
    parts: list[str] = []
    if isinstance(value, tuple):
        for item in value:
            if isinstance(item, tuple):
                for pair in item:
                    if isinstance(pair, tuple) and len(pair) == 2:
                        key, pair_value = pair
                        if key in {"commonName", "organizationName"}:
                            parts.append(str(pair_value))
    return ", ".join(parts)


def _extract_title(html: str) -> str:
    match = TITLE_RE.search(html)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def _selected_headers(headers: dict[str, str]) -> dict[str, str]:
    selected = {}
    for key, value in headers.items():
        normalized = key.lower()
        if normalized in {"server", "content-type", "location", "strict-transport-security", "x-frame-options"}:
            selected[normalized] = value
    return selected


def _header_value(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def _txt_enrichment_results(domain: str, value: str) -> list[AdapterResult]:
    results: list[AdapterResult] = []
    lowered = value.lower()
    if lowered.startswith("v=spf1"):
        results.append(
            AdapterResult(
                source="dns_domain",
                target=domain,
                url=f"SPF {domain}: {_spf_summary(value)}",
                platform="mail_security",
                confidence="medium",
                raw_reference=f"SPF {domain} -> {value}",
            )
        )
    for provider, markers in PROVIDER_HINTS.items():
        if any(marker in lowered for marker in markers):
            results.append(
                AdapterResult(
                    source="dns_domain",
                    target=domain,
                    url=f"{provider.title()} provider hint: {value}",
                    platform="provider_hint",
                    confidence="low",
                    raw_reference=f"Provider hint {provider}: {value}",
                )
            )
    return results


def _provider_hint_results(source: str, target: str, value: str | dict[str, list[str]]) -> list[AdapterResult]:
    if isinstance(value, dict):
        return [
            AdapterResult(
                source=source,
                target=target,
                url=f"{provider.title()} provider hint",
                platform="provider_hint",
                confidence="low",
                raw_reference=f"Provider hint {provider}: {', '.join(evidence)}",
            )
            for provider, evidence in sorted(value.items())
        ]
    lowered = value.lower()
    results: list[AdapterResult] = []
    for provider, markers in PROVIDER_HINTS.items():
        if any(marker in lowered for marker in markers):
            results.append(
                AdapterResult(
                    source=source,
                    target=target,
                    url=f"{provider.title()} provider hint: {value}",
                    platform="provider_hint",
                    confidence="low",
                    raw_reference=f"Provider hint {provider}: {value}",
                )
            )
    return results


def _record_provider_evidence(evidence: dict[str, list[str]], value: str) -> None:
    lowered = value.lower()
    for provider, markers in PROVIDER_HINTS.items():
        if any(marker in lowered for marker in markers):
            entries = evidence.setdefault(provider, [])
            if value not in entries:
                entries.append(value)


def _spf_summary(value: str) -> str:
    mechanisms = value.split()
    includes = [item.removeprefix("include:") for item in mechanisms if item.startswith("include:")]
    policy = next((item for item in reversed(mechanisms) if item in {"-all", "~all", "?all", "+all"}), "")
    parts = []
    if includes:
        parts.append(f"includes={', '.join(includes)}")
    if policy:
        parts.append(f"policy={policy}")
    return "; ".join(parts) or value


def _dmarc_summary(value: str) -> str:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    policy = next((part for part in parts if part.lower().startswith("p=")), "")
    rua = next((part for part in parts if part.lower().startswith("rua=")), "")
    summary_parts = []
    if policy:
        summary_parts.append(policy)
    if rua:
        summary_parts.append(rua)
    return "; ".join(summary_parts) or value


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
    if normalized == "cname":
        return "cname"
    if normalized == "mail_security":
        return "mail_security"
    if normalized == "provider_hint":
        return "provider"
    return "note"


def _email_entity_type(platform: str) -> str:
    normalized = platform.strip().lower()
    if normalized == "email_target":
        return "email"
    if normalized == "email_domain":
        return "domain"
    if normalized == "mx":
        return "mx"
    if normalized in {"spf", "dmarc"}:
        return "mail_security"
    if normalized == "provider_hint":
        return "provider"
    return "note"


def _web_entity_type(platform: str) -> str:
    normalized = platform.strip().lower()
    if normalized in {"web_endpoint", "http_redirect", "tls_certificate"}:
        return normalized
    return "url"


def _normalize_dns_value(record_type: str, value: str) -> str:
    cleaned = value.strip()
    if record_type == "MX":
        parts = cleaned.split(maxsplit=1)
        if len(parts) == 2 and parts[0].isdigit():
            cleaned = parts[1]
    if record_type in {"MX", "NS", "CNAME"}:
        cleaned = cleaned.rstrip(".")
    if record_type == "TXT":
        cleaned = cleaned.strip('"')
    return cleaned


def normalize_email(value: str) -> str:
    email = value.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError(f"Invalid email address: {value}")
    local_part, domain = email.rsplit("@", 1)
    if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        raise ValueError(f"Invalid email address: {value}")
    return f"{local_part}@{normalize_domain(domain)}"


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
