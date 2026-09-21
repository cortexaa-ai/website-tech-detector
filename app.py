"""Website technology detector.

Standard library only. Run:  python app.py   then open http://localhost:8000
"""
import base64
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import siteinfo

HOST, PORT = "127.0.0.1", 8000
BASE = Path(__file__).resolve().parent
TIMEOUT = 10            # seconds per request
MAX_PAGE = 3_000_000    # bytes of HTML to read
MAX_SCRIPT = 2_000_000  # bytes per JS bundle to read
MAX_SCRIPTS = 5         # same-site JS bundles to inspect
MAX_REDIRECTS = 5
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")

# Result sections, in display order. Each category belongs to exactly one group;
# a signature can override its group with "group" (e.g. Next.js is a web framework but lives in Frontend).
GROUPS = [
    ("Frontend", ["JavaScript framework", "JavaScript library", "UI framework", "CSS-in-JS",
                  "Fonts", "Build tool", "Performance"]),
    ("Backend", ["Web framework", "Programming language", "Database", "Web server", "Operating system"]),
    ("CMS & site builders", ["CMS", "Page builder", "Ecommerce", "Static site generator"]),
    ("Hosting & infrastructure", ["Hosting", "CDN", "Cache"]),
    ("Marketing & analytics", ["Analytics", "Advertising", "Tag manager", "Marketing automation",
                               "Live chat", "Email marketing"]),
    ("Security & privacy", ["Security", "Cookie consent"]),
    ("Other", ["Payments", "Monitoring", "Maps", "Video", "Misc"]),
]
CATEGORY_GROUP = {c: g for g, cats in GROUPS for c in cats}
CATEGORY_ORDER = [c for _, cats in GROUPS for c in cats]


class DetectError(Exception):
    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------- signatures

class Pattern:
    """A regex, optionally suffixed with \\;version:<template> (Wappalyzer style), e.g.
    "gtag/js\\?id=G-\\;version:GA4" or "jquery-([\\d.]+)\\.js\\;version:\\1"."""

    def __init__(self, source):
        regex, _, self.template = source.partition(r"\;version:")
        self.rx = re.compile(regex, re.I)

    def search(self, text):
        return self.rx.search(text)

    def version(self, m):
        if self.template:
            v = re.sub(r"\\(\d)", lambda g: m.group(int(g.group(1))) or "", self.template)
        else:
            v = next((g for g in m.groups() if g), None)
        return (v or "").strip().rstrip(".") or None


def _load_signatures():
    raw = json.loads((BASE / "signatures.json").read_text(encoding="utf-8"))
    sigs = {}
    for name, s in raw.items():
        def rx(p, name=name):
            try:
                return Pattern(p)
            except (re.error, IndexError) as e:
                raise SystemExit(f"signatures.json: bad regex in {name!r}: {p!r} ({e})")

        def as_list(v):
            return [v] if isinstance(v, str) else (v or [])

        sigs[name] = {
            "cat": s.get("cat", "Misc"),
            "group": s.get("group") or CATEGORY_GROUP.get(s.get("cat"), "Other"),
            **{k: [rx(p) for p in as_list(s.get(k))] for k in ("html", "scripts", "css", "url", "dns", "js")},
            "headers": {k.lower(): rx(v) for k, v in s.get("headers", {}).items()},
            "meta": {k.lower(): rx(v) for k, v in s.get("meta", {}).items()},
            "cookies": [(rx(k), rx(v)) for k, v in s.get("cookies", {}).items()],
            "implies": as_list(s.get("implies")),
        }
    for name, s in sigs.items():
        if s["cat"] not in CATEGORY_GROUP:
            raise SystemExit(f"signatures.json: {name!r} has unknown category {s['cat']!r}")
        for imp in s["implies"]:
            if imp not in sigs:
                raise SystemExit(f"signatures.json: {name!r} implies unknown technology {imp!r}")
    return sigs


SIGS = _load_signatures()


# ---------------------------------------------------------------- fetching

def check_public(url):
    """Refuse anything that isn't a public http(s) address (blocks localhost, LAN, cloud metadata)."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise DetectError("Only http:// and https:// URLs are supported.", 400)
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise DetectError(f"Could not resolve host {p.hostname!r}.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise DetectError(f"{p.hostname} resolves to a private/internal address ({ip}); refusing to scan it.", 400)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # we follow redirects ourselves so every hop gets check_public()


def _opener(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


def _decode(raw, headers):
    enc = (headers.get("Content-Encoding") or "").lower()
    try:
        if "gzip" in enc:
            raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw)
        elif "deflate" in enc:
            try:
                raw = zlib.decompressobj().decompress(raw)
            except zlib.error:
                raw = zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw)
    except zlib.error:
        pass
    m = re.search(r"charset=[\"']?([\w-]+)", headers.get("Content-Type") or "", re.I)
    try:
        return raw.decode(m.group(1) if m else "utf-8", errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _request(url, verify, limit, dest="document"):
    # Sites like facebook.com reject a Chrome User-Agent that lacks Chrome's Sec-Fetch-* headers.
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" if dest == "document" else "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Sec-Fetch-Dest": dest,
        "Sec-Fetch-Mode": "navigate" if dest == "document" else "no-cors",
        "Sec-Fetch-Site": "none" if dest == "document" else "same-site",
    }
    if dest == "document":
        headers.update({"Sec-Fetch-User": "?1", "Upgrade-Insecure-Requests": "1"})
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = _opener(verify).open(req, timeout=TIMEOUT)
    except HTTPError as e:  # 3xx/4xx/5xx still carry useful headers and HTML
        resp = e
    with resp:
        try:
            raw = resp.read(limit) if resp.fp else b""
        except OSError:
            raw = b""
        return resp.getcode(), resp.headers, _decode(raw, resp.headers)


def _request_tls_fallback(url, limit, state, notes):
    try:
        return _request(url, state["verify"], limit)
    except URLError as e:
        if state["verify"] and isinstance(e.reason, ssl.SSLCertVerificationError):
            state["verify"] = False
            notes.append(f"TLS certificate is not valid ({e.reason.verify_message}); scanned anyway.")
            return _request(url, False, limit)
        raise DetectError(f"Could not connect: {e.reason}")
    except TimeoutError:
        raise DetectError(f"Timed out after {TIMEOUT}s.")
    except OSError as e:
        raise DetectError(f"Connection failed: {e}")


def fetch_page(url, notes):
    state = {"verify": True}
    set_cookies = []
    for _ in range(MAX_REDIRECTS + 1):
        check_public(url)
        status, headers, body = _request_tls_fallback(url, MAX_PAGE, state, notes)
        set_cookies += headers.get_all("Set-Cookie") or []
        location = headers.get("Location")
        if status in (301, 302, 303, 307, 308) and location:
            url = urljoin(url, location)
            continue
        return {"url": url, "status": status, "headers": headers, "html": body,
                "set_cookies": set_cookies, "verify": state["verify"]}
    raise DetectError("Too many redirects.")


def fetch_script(url, verify):
    if url.startswith("data:"):  # inline script, e.g. facebook.com's base64 bundles
        meta, _, data = url.partition(",")
        try:
            raw = base64.b64decode(data) if meta.endswith(";base64") else unquote(data).encode()
        except ValueError:
            return None
        return "inline script", raw[:MAX_SCRIPT].decode("utf-8", errors="replace")
    try:
        check_public(url)
        status, _, body = _request(url, verify, MAX_SCRIPT, dest="script")
        return (url, body) if status == 200 else None
    except (DetectError, OSError):
        return None


def dns_names(host):
    """Canonical name + CNAME aliases (e.g. foo.cdn.cloudflare.net)."""
    try:
        name, aliases, _ = socket.gethostbyname_ex(host)
        return sorted({n for n in [name, *aliases] if n})
    except OSError:
        return []


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.links, self.meta = [], [], {}
        self.title, self._in_title = "", False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"].strip())
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if "modulepreload" in rel or ("preload" in rel and a.get("as") == "script"):
                self.scripts.append(a["href"].strip())
            else:
                self.links.append(a["href"].strip())
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if key and "content" in a:
                self.meta.setdefault(key, []).append(a["content"])
        elif tag == "title" and not self.title:  # later <title>s belong to inline SVGs
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 300:
            self.title += data


# ---------------------------------------------------------------- matching

def _short(s, n=90):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _tech(name, version, confidence, evidence):
    sig = SIGS[name]
    return {"name": name, "category": sig["cat"], "group": sig["group"], "version": version,
            "confidence": confidence, "evidence": evidence}


def analyze(ctx):
    found = {}
    for name, sig in SIGS.items():
        evidence, version = [], None

        def hit(label, p, m):
            nonlocal version
            evidence.append(label)
            version = version or p.version(m)

        for p in sig["html"]:
            if m := p.search(ctx["html"]):
                hit(f'HTML contains "{_short(m.group(0), 60)}"', p, m)
                continue
            # Tools injected at runtime by a tag manager / loader script (GTM, HubSpot, Clarity).
            for src, body in ctx["loaders"]:
                if (m := p.search(body)) and m.group(0).lower() not in LOADER_NOISE:
                    hit(f'Loaded by {_short(src, 60)} ("{_short(m.group(0), 50)}")', p, m)
                    break
        for key, label in (("scripts", "Script"), ("css", "Stylesheet"), ("url", "URL"), ("dns", "DNS name")):
            for p in sig[key]:
                for value in ctx[key]:
                    if m := p.search(value):
                        hit(f"{label}: {_short(value)}", p, m)
                        break
        for p in sig["js"]:
            for src, body in ctx["js"]:
                if m := p.search(body):
                    hit(f'JS bundle {_short(src.rsplit("/", 1)[-1], 50)} contains "{_short(m.group(0), 50)}"', p, m)
                    break
        for key, p in sig["headers"].items():
            for value in ctx["headers"].get(key, []):
                if m := p.search(value):
                    hit(f"Header {key}: {_short(value, 70)}", p, m)
                    break
        for key, p in sig["meta"].items():
            for value in ctx["meta"].get(key, []):
                if m := p.search(value):
                    hit(f'<meta {key}="{_short(value, 60)}">', p, m)
                    break
        for name_p, value_p in sig["cookies"]:
            for cname, cvalue in ctx["cookies"]:
                if name_p.rx.fullmatch(cname) and (m := value_p.search(cvalue)):
                    hit(f"Cookie {cname}", value_p, m)
                    break

        if evidence:
            found[name] = _tech(name, version, "high" if len(evidence) > 1 else "medium", evidence)

    queue = list(found)
    while queue:
        src = queue.pop()
        for imp in SIGS[src]["implies"]:
            if imp not in found:
                found[imp] = _tech(imp, None, "implied", [f"Implied by {src}"])
                queue.append(imp)
    return found


LOADER_HOSTS = ("googletagmanager.com", "hs-scripts.com", "clarity.ms")
# Strings baked into every GTM container's runtime, so they prove nothing when found inside one.
LOADER_NOISE = {"fls.doubleclick.net", "googleads.g.doubleclick.net", "googleadservices.com/pagead/conversion"}
MAX_LOADERS = 4


def loader_urls(html, scripts):
    """Scripts that inject other tools at runtime: fetching them reveals what a real browser would load."""
    urls = [s for s in scripts if any((urlparse(s).hostname or "").endswith(h) for h in LOADER_HOSTS)]
    # GTM and Clarity are usually injected by an inline snippet, so rebuild their URLs from the IDs.
    urls += [f"https://www.googletagmanager.com/gtm.js?id={i}" for i in re.findall(r"\bGTM-[A-Z0-9]{4,10}\b", html)]
    urls += [f"https://www.clarity.ms/tag/{i}" for i in
             re.findall(r"[\"']clarity[\"']\s*,\s*[\"']script[\"']\s*,\s*[\"']([a-z0-9]+)[\"']", html)]
    return list(dict.fromkeys(urls))[:MAX_LOADERS]


# ---------------------------------------------------------------- pipeline

def detect(target):
    target = target.strip()
    if not target:
        raise DetectError("Please enter a URL.", 400)
    t0 = time.monotonic()
    notes = []

    candidates = [target] if re.match(r"^https?://", target, re.I) else ["https://" + target, "http://" + target]
    for i, url in enumerate(candidates):
        try:
            page = fetch_page(url, notes)
            break
        except DetectError as e:
            if e.status == 400 or i == len(candidates) - 1:
                raise

    final = page["url"]
    host = urlparse(final).hostname
    parser = _PageParser()
    try:
        parser.feed(page["html"])
    except Exception:  # malformed markup: regex-based HTML checks still run
        pass

    scripts = [urljoin(final, s) for s in parser.scripts]
    links = [urljoin(final, h) for h in parser.links]

    # Bundled SPAs (React/Vue/Angular) often leave no trace in HTML, so peek into their JS.
    # Same-site scripts first, then others (big sites serve bundles from their own CDN domain, e.g. fbcdn.net).
    site = ".".join(host.split(".")[-2:])
    loaders = loader_urls(page["html"], scripts)
    inline = [s for s in scripts if s.startswith("data:")]
    remote = [s for s in scripts if not s.startswith("data:") and s not in loaders]
    same = [s for s in remote if (urlparse(s).hostname or "").endswith(site)]
    own = inline + (same + [s for s in remote if s not in same])[:MAX_SCRIPTS]
    with ThreadPoolExecutor(max_workers=MAX_SCRIPTS + MAX_LOADERS + 1) as pool:
        dns_future = pool.submit(dns_names, host)
        server_ip = _resolve(host)
        info_future = pool.submit(siteinfo.gather, host, server_ip)
        loader_futures = [pool.submit(fetch_script, u, page["verify"]) for u in loaders]
        js = [r for r in pool.map(lambda u: fetch_script(u, page["verify"]), own) if r]
        loaded = [r for r in (f.result() for f in loader_futures) if r]
        dns = dns_future.result()
        info = info_future.result()

    headers = {}
    for k, v in page["headers"].items():
        headers.setdefault(k.lower(), []).append(v)
    cookies = []
    for c in page["set_cookies"]:
        name, _, value = c.split(";", 1)[0].partition("=")
        cookies.append((name.strip(), value.strip()))

    found = analyze({
        "html": page["html"], "scripts": scripts, "css": links, "url": [final], "dns": dns,
        "js": js + loaded, "loaders": loaded, "headers": headers, "meta": parser.meta, "cookies": cookies,
    })

    status = page["status"]
    if status >= 400:
        challenge = "cf-mitigated" in headers or re.search(r"Just a moment|Attention Required", page["html"])
        notes.append(f"Site answered HTTP {status}"
                     + (" with a bot challenge; results are limited to headers/DNS." if challenge else "; results may be incomplete."))
    if not page["html"].strip():
        notes.append("Page body was empty.")

    rank = {"high": 0, "medium": 1, "implied": 2}
    by_cat = {}  # (group, category) -> technologies
    for t in sorted(found.values(), key=lambda t: (rank[t["confidence"]], t["name"].lower())):
        by_cat.setdefault((t["group"], t["category"]), []).append(t)
    groups = []
    for group, _ in GROUPS:
        cats = sorted((c for g, c in by_cat if g == group), key=CATEGORY_ORDER.index)
        if cats:
            groups.append({"name": group, "count": sum(len(by_cat[(group, c)]) for c in cats),
                           "categories": [{"name": c, "technologies": by_cat[(group, c)]} for c in cats]})

    return {
        "input": target,
        "final_url": final,
        "status": status,
        "title": _short(parser.title, 150),
        "server_ip": server_ip,
        "info": info,
        "dns": dns,
        "scripts_inspected": len(js) + len(loaded),
        "count": len(found),
        "elapsed_ms": int((time.monotonic() - t0) * 1000),
        "notes": notes,
        "groups": groups,
    }


# ---------------------------------------------------------------- web server

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path)
        if path.path in ("/", "/index.html"):
            self._send(200, (BASE / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path.path == "/api/detect":
            target = parse_qs(path.query).get("url", [""])[0]
            try:
                code, body = 200, detect(target)
            except DetectError as e:
                code, body = e.status, {"error": str(e)}
            except Exception as e:
                self.log_error("detect(%r) crashed: %r", target, e)
                code, body = 500, {"error": f"Unexpected error: {e}"}
            self._send(code, json.dumps(body).encode(), "application/json")
        else:
            self._send(404, b"Not found", "text/plain")


if __name__ == "__main__":
    import sys
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else PORT  # python app.py 8001
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Loaded {len(SIGS)} technology signatures.")
    print(f"Open http://localhost:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
