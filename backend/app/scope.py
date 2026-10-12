from __future__ import annotations
import ipaddress, socket, posixpath
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode, unquote
from .redaction import contains_sensitive_query

class ScopeViolation(ValueError): pass


def _policy_path(path: str) -> str:
    """Canonicalize a path for exclusion checks without changing the request URL."""
    decoded = unquote(path or "/").replace("\\", "/")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    normalized = posixpath.normpath(decoded)
    return normalized if normalized.startswith("/") else "/" + normalized


def _excluded_path(path: str, prefix: str) -> bool:
    candidate = _policy_path(path)
    raw_prefix = str(prefix or "").strip()
    if not raw_prefix:
        return False
    if raw_prefix.endswith("*"):
        return candidate.startswith(_policy_path(raw_prefix[:-1]))
    normalized_prefix = _policy_path(raw_prefix).rstrip("/") or "/"
    return candidate == normalized_prefix or normalized_prefix == "/" or candidate.startswith(normalized_prefix + "/")

@dataclass(frozen=True)
class ScopePolicy:
    root_url: str
    allowed_hosts: frozenset[str]
    excluded_prefixes: tuple[str, ...] = field(default_factory=tuple)
    allow_private_targets: bool = False
    allowed_ports: dict[str, frozenset[int]] = field(default_factory=dict)

    @classmethod
    def from_root(cls, root_url: str, exclusions: list[str] | None = None, allow_private_targets: bool = False, allowed_hosts: list[str] | None = None):
        raw = str(root_url).strip()
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in raw) or "\\" in raw:
            raise ScopeViolation('Control characters and backslashes are forbidden in target URLs')
        try:
            parsed=urlparse(raw)
            _ = parsed.port
        except ValueError as exc:
            raise ScopeViolation('Malformed target URL or port') from exc
        if parsed.scheme.lower() not in {'http','https'} or not parsed.hostname:
            raise ScopeViolation('Target must be an absolute HTTP(S) URL')
        if parsed.username is not None or parsed.password is not None:
            raise ScopeViolation('Credentials embedded in target URLs are not allowed; use an authentication profile')
        host=parsed.hostname.lower().rstrip('.')
        if parsed.port == 0:
            raise ScopeViolation('Ports must be between 1 and 65535')
        scheme=parsed.scheme.lower()
        root_port=parsed.port or (443 if scheme=='https' else 80)
        ports={host:{root_port}}
        # The opposite standard web port is permitted only when using the standard port
        # in the root URL, so redirects/mixed-content inventory remains assessable.
        if parsed.port is None:
            ports[host]={80,443}
        hosts={host}
        for item in allowed_hosts or []:
            item=str(item).strip().lower().rstrip('.')
            if not item: continue
            if '://' in item:
                try:
                    ap=urlparse(item)
                    _ = ap.port
                except ValueError as exc:
                    raise ScopeViolation(f'Invalid allowed host URL: {item}') from exc
                if ap.scheme.lower() not in {'http','https'} or not ap.hostname or ap.username is not None or ap.password is not None or ap.path not in {'','/'} or ap.query or ap.fragment:
                    raise ScopeViolation(f'Invalid allowed host URL: {item}')
                if ap.port == 0:
                    raise ScopeViolation(f'Invalid allowed port: {ap.port}')
                ah=ap.hostname.lower().rstrip('.'); port=ap.port if ap.port is not None else (443 if ap.scheme.lower()=='https' else 80)
                hosts.add(ah); ports.setdefault(ah,set()).add(port)
            else:
                # host:port is supported; bracketed IPv6 literals are handled separately.
                ah=item; explicit_port=None
                if item.startswith('[') and ']:' in item:
                    ah, p=item[1:].split(']:',1); explicit_port=int(p)
                elif item.count(':')==1:
                    maybe_host, maybe_port=item.rsplit(':',1)
                    if maybe_port.isdigit(): ah=maybe_host; explicit_port=int(maybe_port)
                ah=ah.strip('[]').lower().rstrip('.')
                if not ah: raise ScopeViolation(f'Invalid allowed host: {item}')
                if explicit_port is not None and not (1 <= explicit_port <= 65535): raise ScopeViolation(f'Invalid allowed port: {explicit_port}')
                hosts.add(ah)
                if explicit_port is not None:
                    ports.setdefault(ah,set()).add(explicit_port)
                elif ah != host:
                    # Additional host without an explicit port is limited to standard web ports.
                    ports.setdefault(ah,set()).update({80,443})
        normalized=urlunparse((scheme, parsed.netloc.lower(), parsed.path or '/', '', parsed.query, ''))
        obj=cls(normalized,frozenset(hosts),tuple(exclusions or ()),allow_private_targets,{k:frozenset(v) for k,v in ports.items()})
        if not allow_private_targets:
            for h in hosts: obj._reject_private_host(h)
        return obj

    @staticmethod
    def _reject_private_host(host: str):
        try:
            literal=ipaddress.ip_address(host)
            addresses=[literal]
        except ValueError:
            try:
                infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise ScopeViolation(f'Cannot resolve target host {host}; refusing to scan an unresolved host') from exc
            addresses=[]
            for info in infos:
                try: addresses.append(ipaddress.ip_address(info[4][0]))
                except ValueError: continue
        if not addresses:
            raise ScopeViolation(f'No usable IP addresses found for target host {host}')
        blocked=[str(ip) for ip in addresses if not ip.is_global]
        if blocked:
            raise ScopeViolation('Private, loopback, link-local, reserved, multicast, or otherwise non-global targets are disabled by policy')

    def is_allowed(self, url: str) -> bool:
        try:
            raw = str(url)
            if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in raw) or "\\" in raw: return False
            parsed=urlparse(raw); host=(parsed.hostname or '').lower().rstrip('.')
            if parsed.port == 0: return False
            if parsed.scheme.lower() not in {'http','https'} or not host or parsed.username is not None or parsed.password is not None: return False
            port=parsed.port if parsed.port is not None else (443 if parsed.scheme.lower()=='https' else 80)
            if host not in self.allowed_hosts or port not in self.allowed_ports.get(host,frozenset({80,443})): return False
            path=parsed.path or '/'
            if contains_sensitive_query(str(url)): return False
            return not any(_excluded_path(path,p) for p in self.excluded_prefixes)
        except Exception: return False

    def validate_url(self, url: str) -> str:
        raw = str(url)
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in raw) or "\\" in raw:
            raise ScopeViolation('Control characters and backslashes are forbidden in URLs')
        try:
            parsed=urlparse(raw)
            _ = parsed.port
        except ValueError as exc:
            raise ScopeViolation('Malformed URL or port') from exc
        if parsed.scheme.lower() not in {'http','https'} or not parsed.hostname:
            raise ScopeViolation('Only absolute HTTP(S) URLs are allowed')
        if parsed.username is not None or parsed.password is not None:
            raise ScopeViolation('Credentials embedded in URLs are forbidden')
        host=parsed.hostname.lower().rstrip('.')
        if parsed.port == 0:
            raise ScopeViolation('Ports must be between 1 and 65535')
        port=parsed.port if parsed.port is not None else (443 if parsed.scheme.lower()=='https' else 80)
        if host not in self.allowed_hosts: raise ScopeViolation(f'Host outside configured scope: {host}')
        if port not in self.allowed_ports.get(host,frozenset({80,443})):
            raise ScopeViolation(f'Port outside configured scope: {port}')
        path=parsed.path or '/'
        if contains_sensitive_query(raw):
            raise ScopeViolation('URLs with credential-like query parameters are not requested or persisted; exclude or test these separately')
        if any(_excluded_path(path,p) for p in self.excluded_prefixes): raise ScopeViolation(f'Path excluded by scope policy: {path}')
        if not self.allow_private_targets: self._reject_private_host(host)
        # Normalize common tracking parameters to avoid crawling duplicate URLs indefinitely.
        try:
            pairs=parse_qsl(parsed.query,keep_blank_values=True)
            pairs=[(k,v) for k,v in pairs if not (k.lower().startswith('utm_') or k.lower() in {'gclid','fbclid','msclkid','yclid'})]
            query=urlencode(pairs,doseq=True)
        except Exception: query=parsed.query
        return urlunparse((parsed.scheme.lower(),parsed.netloc.lower(),path,'',query,''))

    def join(self, base: str, value: str) -> str | None:
        try: return self.validate_url(urljoin(base,value))
        except Exception: return None
