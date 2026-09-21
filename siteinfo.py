"""Who/where/when facts about a site: domain registration (RDAP), hosting network (IP RDAP),
TLS certificate, and email/verification services from DNS (DNS-over-HTTPS). Standard library only."""
import json
import socket
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import quote

TIMEOUT = 8

MX_PROVIDERS = {
    "google.com": "Google Workspace", "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365", "protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho Mail", "zoho.eu": "Zoho Mail", "yandex.net": "Yandex Mail",
    "icloud.com": "iCloud Mail", "secureserver.net": "GoDaddy Email", "titan.email": "Titan Email",
    "privateemail.com": "Namecheap Private Email", "hostinger.com": "Hostinger Email",
    "mimecast.com": "Mimecast", "pphosted.com": "Proofpoint", "messagelabs.com": "Broadcom Email Security",
    "barracudanetworks.com": "Barracuda", "amazonaws.com": "Amazon SES/WorkMail", "mailgun.org": "Mailgun",
    "fastmail.com": "Fastmail", "protonmail.ch": "Proton Mail", "ovh.net": "OVH Mail",
}

SPF_SERVICES = {
    "_spf.google.com": "Google Workspace", "spf.protection.outlook.com": "Microsoft 365",
    "sendgrid.net": "SendGrid", "mailgun.org": "Mailgun", "amazonses.com": "Amazon SES",
    "servers.mcsv.net": "Mailchimp", "spf.mandrillapp.com": "Mailchimp Transactional",
    "hubspotemail.net": "HubSpot", "hubspot.com": "HubSpot", "_spf.salesforce.com": "Salesforce", "exacttarget.com": "Salesforce Marketing Cloud",
    "mail.zendesk.com": "Zendesk", "freshdesk.com": "Freshdesk", "helpscoutemail.com": "Help Scout",
    "spf.mtasv.net": "Postmark", "sparkpostmail.com": "SparkPost", "mailjet.com": "Mailjet",
    "zoho.com": "Zoho", "zoho.eu": "Zoho", "mktomail.com": "Marketo", "intercom.io": "Intercom",
    "stspg-customer.com": "Atlassian Statuspage", "shopify.com": "Shopify", "brevo.com": "Brevo",
    "sendinblue.com": "Brevo", "klaviyo.com": "Klaviyo", "customer.io": "Customer.io",
}

TXT_VERIFICATIONS = {
    "google-site-verification": "Google Search Console", "facebook-domain-verification": "Meta Business",
    "ms=": "Microsoft 365", "apple-domain-verification": "Apple", "atlassian-domain-verification": "Atlassian",
    "stripe-verification": "Stripe", "docusign": "DocuSign", "adobe-idp-site-verification": "Adobe",
    "openai-domain-verification": "OpenAI", "zoom_verify": "Zoom", "slack-domain-verification": "Slack",
    "hubspot-developer-verification": "HubSpot", "globalsign-domain-verification": "GlobalSign",
    "yandex-verification": "Yandex Webmaster", "pinterest-site-verification": "Pinterest",
    "canva-site-verification": "Canva", "miro-verification": "Miro", "dropbox-domain-verification": "Dropbox",
    "cisco-ci-domain-verification": "Cisco Webex", "have-i-been-pwned-verification": "Have I Been Pwned",
    "notion-domain-verification": "Notion", "figma-domain-verification": "Figma",
}


def _get_json(url, accept="application/json"):
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "website-tech-detector"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read(2_000_000).decode("utf-8", "replace"))


def _date(s):
    return s[:10] if s else None


def _vcard(entity):
    """Pull name / org / country out of an RDAP entity's jCard."""
    out = {}
    for field in (entity.get("vcardArray") or [None, []])[1]:
        key, params, _, value = (field + [None] * 4)[:4]
        if key == "fn" and value:
            out["name"] = value
        elif key == "org" and value:
            out["org"] = value if isinstance(value, str) else " ".join(value)
        elif key == "adr":
            label = (params or {}).get("label")
            if isinstance(value, list) and value and value[-1]:
                out["country"] = value[-1]
            elif label:
                out["country"] = label.strip().splitlines()[-1]
    return out


def _entities(obj, role):
    found = []
    for e in obj.get("entities") or []:
        if role in (e.get("roles") or []):
            found.append(e)
        found += _entities(e, role)
    return found


def _redacted(v):
    return not v or "redacted" in v.lower() or "privacy" in v.lower() or "not disclosed" in v.lower()


def domain_info(host):
    labels = host.lower().rstrip(".").split(".")
    if labels[0] == "www":
        labels = labels[1:]
    # Try the registrable domain (example.com), then one level up for things like example.co.uk.
    for n in (2, 3):
        if len(labels) < n:
            break
        domain = ".".join(labels[-n:])
        try:
            data = _get_json(f"https://rdap.org/domain/{quote(domain)}", "application/rdap+json")
        except HTTPError as e:
            if e.code == 404:
                continue
            return {"domain": domain, "error": f"RDAP lookup failed (HTTP {e.code})"}
        except (OSError, ValueError) as e:
            return {"domain": domain, "error": f"RDAP lookup failed ({e})"}

        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or []}
        created = events.get("registration")
        info = {
            "domain": data.get("ldhName", domain).lower(),
            "registered": _date(created),
            "expires": _date(events.get("expiration")),
            "updated": _date(events.get("last changed")),
            "age": _age(created),
            "status": data.get("status") or [],
            "nameservers": sorted({(ns.get("ldhName") or "").lower() for ns in data.get("nameservers") or []} - {""}),
        }
        registrar = next((_vcard(e) for e in _entities(data, "registrar")), {})
        info["registrar"] = registrar.get("name") or registrar.get("org")
        owner = next((_vcard(e) for e in _entities(data, "registrant")), {})
        info["owner"] = next((v for v in (owner.get("org"), owner.get("name")) if not _redacted(v)), None)
        info["owner_country"] = owner.get("country") if not _redacted(owner.get("country")) else None
        info["owner_hidden"] = not info["owner"]
        return info
    return {"domain": ".".join(labels[-2:]), "error": "No public registration data for this domain extension (RDAP unsupported)."}


def _age(iso):
    if not iso:
        return None
    try:
        start = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    days = (datetime.now(timezone.utc) - start).days
    years, rem = divmod(days, 365)
    months = rem // 30
    return f"{years} years, {months} months" if years else f"{months} months, {rem % 30} days"


def ip_info(ip):
    if not ip:
        return {"error": "Could not resolve the server IP."}
    try:
        data = _get_json(f"https://rdap.org/ip/{ip}", "application/rdap+json")
    except (OSError, ValueError) as e:
        return {"ip": ip, "error": f"IP lookup failed ({e})"}
    org = next((_vcard(e) for role in ("registrant", "administrative", "abuse")
                for e in _entities(data, role) if _vcard(e)), {})
    cidrs = data.get("cidr0_cidrs") or []
    network = (f"{cidrs[0].get('v4prefix') or cidrs[0].get('v6prefix')}/{cidrs[0].get('length')}" if cidrs
               else f"{data.get('startAddress')} - {data.get('endAddress')}")
    return {
        "ip": ip,
        "network_name": data.get("name"),
        "organization": org.get("org") or org.get("name"),
        "country": data.get("country") or org.get("country"),
        "network": network,
        "reverse_dns": _reverse(ip),
    }


def _reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def tls_info(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert, version = tls.getpeercert(), tls.version()
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": e.verify_message}
    except OSError as e:
        return {"error": f"No HTTPS on port 443 ({e})"}

    def name(parts, key):
        return next((v for rdn in parts for k, v in rdn if k == key), None)

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    return {
        "valid": True,
        "issuer": name(cert.get("issuer", ()), "organizationName") or name(cert.get("issuer", ()), "commonName"),
        "subject": name(cert.get("subject", ()), "commonName"),
        "valid_from": datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").date().isoformat(),
        "valid_to": not_after.date().isoformat(),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
        "protocol": version,
        "other_domains": len(sans),
        "sample_domains": sans[:8],
    }


DOH_SERVERS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


def _dns(name, rtype):
    """MX/TXT records via DNS-over-HTTPS (stdlib has no MX/TXT resolver). None means the lookup failed."""
    for server in DOH_SERVERS:
        try:
            data = _get_json(f"{server}?name={quote(name)}&type={rtype}", "application/dns-json")
        except (OSError, ValueError):
            continue
        return [a.get("data", "").strip('"') for a in data.get("Answer") or [] if a.get("type") in (15, 16)]
    return None


def email_info(domain):
    with ThreadPoolExecutor(max_workers=2) as pool:
        mx_f, txt_f = pool.submit(_dns, domain, "MX"), pool.submit(_dns, domain, "TXT")
        mx_raw, txt_raw = mx_f.result(), txt_f.result()
    if mx_raw is None:
        return {"error": "DNS lookup failed (could not reach a DNS-over-HTTPS server)."}
    mx = sorted({r.split()[-1].rstrip(".").lower() for r in mx_raw if r})
    txt = [t.replace('" "', "") for t in txt_raw or []]

    providers = sorted({p for host in mx for suffix, p in MX_PROVIDERS.items() if host.endswith(suffix)})
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
    targets = [p.split(":", 1)[1] if p.startswith("include:") else p.split("=", 1)[1]
               for p in spf.lower().split() if p.startswith(("include:", "redirect="))]
    senders = sorted({s for t in targets for suffix, s in SPF_SERVICES.items() if t.endswith(suffix)})
    verified = sorted({svc for t in txt for key, svc in TXT_VERIFICATIONS.items() if t.lower().startswith(key)})
    return {
        "mx": mx,
        "provider": ", ".join(providers) if providers else ("Custom / self-hosted" if mx else "No email (no MX records)"),
        "sending_services": senders,
        "verified_services": verified,
        "spf": spf or None,
        "dmarc": next((t for t in _dns(f"_dmarc.{domain}", "TXT") or [] if t.lower().startswith("v=dmarc1")), None),
    }


def gather(host, ip):
    with ThreadPoolExecutor(max_workers=3) as pool:
        dom_f = pool.submit(domain_info, host)
        ip_f = pool.submit(ip_info, ip)
        tls_f = pool.submit(tls_info, host)
        dom = dom_f.result()
        email = email_info(dom["domain"])
        return {"domain": dom, "hosting": ip_f.result(), "tls": tls_f.result(), "email": email}
