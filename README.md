# Website Tech Detector

Find out what any website is built with. Paste a URL and get its frontend and backend stack, CMS, hosting, marketing tools and security setup. It also shows the domain's registration date, registrar, hosting company and email provider.

Pure Python standard library. **No `pip install`, no API keys.**

## Features

**Technology detection** (~150 technologies), grouped into sections:

| Section | Examples |
|---|---|
| Frontend | React, Vue.js, Angular, Svelte, Next.js, Nuxt, Tailwind CSS, Bootstrap, jQuery, Framer Motion |
| Backend | Laravel, Django, Rails, Express, ASP.NET, PHP, Python, Node.js, Nginx, Apache, IIS |
| CMS & site builders | WordPress, Shopify, Wix, Webflow, Framer, Squarespace, Drupal, Magento |
| Hosting & infrastructure | Cloudflare, Vercel, Netlify, AWS CloudFront, Fastly, Akamai, GitHub Pages |
| Marketing & analytics | Google Analytics (GA4), GTM, Meta Pixel, LinkedIn Insight, HubSpot, Hotjar, Clarity |
| Security & privacy | reCAPTCHA, HSTS, CSP, Cloudflare Turnstile, OneTrust, Cookiebot |

Each result shows its **version** (when exposed), a **confidence level**, and the **evidence** that triggered it.

**Site info**

- **Domain**: registration and expiry dates, age, registrar, name servers, owner (when not privacy-protected)
- **Hosting**: server IP, hosting company, country, IP range
- **SSL certificate**: issuer, validity dates, days left, TLS version
- **Email & services**: email provider (Google Workspace, Microsoft 365…), sending services (SendGrid, Amazon SES…), domains verified with services like Slack, Notion and Stripe, and DMARC status

## Quick start

Requires **Python 3.8+**.

```bash
git clone https://github.com/cortexaa-ai/website-tech-detector.git
cd website-tech-detector
python app.py
```

Open **http://localhost:8000**, enter a site like `wordpress.org`, and click **Detect**.

Use a different port:

```bash
python app.py 8001
```

### API

```
GET /api/detect?url=example.com
```

Returns JSON with `final_url`, `status`, `title`, `info` (domain / hosting / tls / email) and `groups` → `categories` → `technologies`.

## How it works

1. **Fetches the page** like a real Chrome browser, following redirects. Every hop is checked so private or internal addresses can't be scanned.
2. **Collects signals**: response headers, cookies, `<meta>` tags, script and stylesheet URLs, the HTML itself, and DNS CNAME aliases.
3. **Inspects JavaScript bundles**, including inline `data:` scripts, to spot frameworks that leave no trace in HTML (single-page apps).
4. **Reads tag-manager containers** (Google Tag Manager, HubSpot and Clarity loaders) to find tools a browser would inject at runtime, such as LinkedIn, Twitter Ads and Floodlight.
5. **Matches everything** against regex rules in `signatures.json`, extracts versions, and adds implied technologies (e.g. WordPress → PHP + MySQL).
6. **Looks up site info** in parallel:
   - [RDAP](https://about.rdap.org/) (the modern WHOIS) for the domain and IP
   - a TLS handshake for the certificate
   - DNS-over-HTTPS (Google, with Cloudflare as a fallback) for MX/TXT records

## Project structure

```
app.py            HTTP server, page fetching, detection engine
siteinfo.py       Domain (RDAP), hosting, SSL and email/DNS lookups
signatures.json   Detection rules, one entry per technology
index.html        Single-page UI
```

## Adding a technology

Add an entry to `signatures.json`. All patterns are case-insensitive regexes.

```json
"My Framework": {
  "cat": "JavaScript framework",
  "html": ["data-myfw-root"],
  "scripts": ["myfw(?:\\.min)?\\.js", "/myfw@([\\d.]+)"],
  "headers": { "x-powered-by": "MyFW(?:/([\\d.]+))?" },
  "cookies": { "myfw_session": "" },
  "meta": { "generator": "^MyFW ([\\d.]+)" },
  "js": ["__MYFW__"],
  "implies": ["Node.js"]
}
```

| Key | Matched against |
|---|---|
| `html` | Page HTML (also tag-manager containers) |
| `scripts` / `css` | `<script src>` / `<link href>` URLs |
| `js` | Contents of fetched JS bundles |
| `headers` | Response header value, by header name |
| `cookies` | Cookie name (regex) → value |
| `meta` | `<meta name/property>` content |
| `url` / `dns` | Final URL / DNS CNAME names |
| `implies` | Other technologies to add when this one is found |
| `group` | Override the section (e.g. put Next.js under Frontend) |

**Versions:** the first capture group becomes the version. For a fixed label, add `\\;version:GA4` to the end of the pattern.

`cat` must be one of the categories listed in `GROUPS` at the top of `app.py`. The server refuses to start if a category is unknown or an `implies` target doesn't exist.

## Limitations

- **Owner details** are usually hidden by GDPR and privacy protection. Registrar and dates are always available.
- **Location** is the server's country, not the owner's.
- The **backend language** is often hidden when a site strips its headers or sits behind a CDN.
- Sites behind **bot protection** (e.g. Cloudflare challenges) return limited results; the tool does not try to bypass them.
- It does **not run a headless browser**, so tools loaded only by complex runtime logic may be missed.
- Some country-code domains have no public RDAP service, so domain info won't be available for them.
