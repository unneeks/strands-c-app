"""web_fetch: read a public web page or API as text, with SSRF protection."""

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

from strands import tool

from .safety import PolicyError, clip, redact

MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "svg", "head", "template"}
    _BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip_depth and data.strip():
            self.parts.append(data)

    def text(self) -> str:
        joined = "".join(self.parts)
        lines = [" ".join(line.split()) for line in joined.splitlines()]
        out, blank = [], 0
        for line in lines:
            blank = blank + 1 if not line else 0
            if blank <= 1:
                out.append(line)
        return "\n".join(out).strip()


def check_url(url: str) -> None:
    """Refuse non-http(s) URLs and any host that resolves to a private/internal address."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise PolicyError("Only http:// and https:// URLs can be fetched.")
    host = parsed.hostname
    if not host:
        raise ValueError("The URL has no host.")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{host}': {exc}") from None
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if getattr(address, "ipv4_mapped", None):
            address = address.ipv4_mapped
        if (
            address.is_private or address.is_loopback or address.is_link_local
            or address.is_reserved or address.is_multicast or address.is_unspecified
        ):
            raise PolicyError(f"'{host}' resolves to an internal address ({address}); fetching it is not allowed.")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # handled manually so every hop is re-validated
        return None


@tool
def web_fetch(url: str, max_chars: int = 20000) -> str:
    """Fetch a public web page or JSON API and return it as readable text.

    Use for documentation, package pages and API references. Internal and private network
    addresses are blocked. Use the search tools to discover URLs first.

    Args:
        url: A full http:// or https:// URL.
        max_chars: Maximum characters to return (1000-50000).
    """
    limit = max(1000, min(int(max_chars), 50000))
    opener = urllib.request.build_opener(_NoRedirect)
    current = url.strip()
    for _ in range(MAX_REDIRECTS + 1):
        check_url(current)
        request = urllib.request.Request(
            current,
            headers={"User-Agent": "coding-agent/1.0", "Accept": "text/html,application/json,text/plain,*/*;q=0.8"},
        )
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
                current = urllib.parse.urljoin(current, exc.headers["Location"])
                continue
            raise ValueError(f"HTTP {exc.code} {exc.reason} for {current}") from None
        except urllib.error.URLError as exc:
            raise ValueError(f"Could not fetch {current}: {exc.reason}") from None
        with response:
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(MAX_BYTES + 1)
            charset = response.headers.get_content_charset() or "utf-8"
        truncated = len(raw) > MAX_BYTES
        text = raw[:MAX_BYTES].decode(charset, "replace")
        if "html" in content_type.lower():
            extractor = _TextExtractor()
            extractor.feed(text)
            text = extractor.text()
        header = f"URL: {current}\nContent-Type: {content_type or 'unknown'}"
        if truncated:
            header += "\n[download truncated at 2 MB]"
        return f"{header}\n---\n{redact(clip(text, limit))}"
    raise ValueError(f"Too many redirects (more than {MAX_REDIRECTS}).")
