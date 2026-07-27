"""Subdomain-takeover detection.

Fingerprint database compiled from EdOverflow's ``can-i-take-over-xyz`` and the
subtake/subjack corpora.  Detection combines the CNAME target (does it point at a
takeover-prone provider?) with the HTTP response body fingerprint (does the page
show the provider's "unclaimed resource" text?).  For NXDOMAIN-class services the
dangling CNAME itself is the signal.

Results are triage signals — always manually verify before reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..net.dns import resolve
from ..net.http import HttpClient

# service, cname substrings, body fingerprints, status, nxdomain-based
_FINGERPRINTS: list[tuple[str, list[str], list[str], str, bool]] = [
    ("AWS/S3", ["s3.amazonaws.com", "s3-website", "s3.dualstack"], ["The specified bucket does not exist"], "vulnerable", False),
    ("AWS/Elastic Beanstalk", ["elasticbeanstalk.com"], [], "vulnerable", True),
    ("Azure", ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
               "blob.core.windows.net", "azure-api.net", "azurehdinsight.net", "azureedge.net",
               "azurefd.net"], [], "vulnerable", True),
    ("GitHub Pages", ["github.io"], ["There isn't a GitHub Pages site here."], "edge", False),
    ("Bitbucket", ["bitbucket.io"], ["Repository not found"], "vulnerable", False),
    ("Heroku", ["herokuapp.com", "herokudns.com", "herokussl.com"],
     ["No such app", "no-such-app.html"], "edge", False),
    ("Fastly", ["fastly.net"], ["Fastly error: unknown domain"], "notvuln", False),
    ("Shopify", ["myshopify.com"], ["Sorry, this shop is currently unavailable"], "edge", False),
    ("Netlify", ["netlify.app", "netlify.com"], ["Not Found - Request ID"], "edge", False),
    ("Ghost", ["ghost.io"], ["The thing you were looking for is no longer here",
                             "Failed to resolve DNS path for this host"], "vulnerable", False),
    ("WordPress.com", ["wordpress.com"], ["Do you want to register"], "vulnerable", False),
    ("Tumblr", ["domains.tumblr.com"], ["Whatever you were looking for doesn't currently exist at this address"], "edge", False),
    ("Pantheon", ["pantheonsite.io"], ["The gods are wise", "404 error unknown site!"], "vulnerable", False),
    ("Readthedocs", ["readthedocs.io"], ["The link you have followed or the URL that you entered does not exist"], "vulnerable", False),
    ("Surge.sh", ["surge.sh"], ["project not found"], "vulnerable", False),
    ("Cargo", ["cargocollective.com", "cargo.site"], ["404 Not Found"], "vulnerable", False),
    ("Webflow", ["proxy-ssl.webflow.com", "webflow.io"], ["The page you are looking for doesn't exist or has been moved"], "edge", False),
    ("Wix", ["wixdns.net"], ["Looks Like This Domain Isn't Connected To A Website Yet"], "edge", False),
    ("Intercom", ["custom.intercom.help"], ["Uh oh. That page doesn't exist"], "edge", False),
    ("Strikingly", ["s.strikinglydns.com"], ["PAGE NOT FOUND"], "vulnerable", False),
    ("Tilda", ["tilda.ws"], ["Please renew your subscription"], "edge", False),
    ("Vercel", ["vercel.app", "cname.vercel-dns.com"], ["DEPLOYMENT_NOT_FOUND"], "edge", False),
    ("JetBrains YouTrack", ["youtrack.cloud"], ["is not a registered InCloud YouTrack"], "vulnerable", False),
    ("Ngrok", ["ngrok.io"], ["not found"], "vulnerable", False),
    ("Gemfury", ["furyns.com"], ["404: This page could not be found"], "vulnerable", False),
    ("Anima", ["animaapp.io"], ["The page you were looking for does not exist"], "vulnerable", False),
    ("Agile CRM", ["agilecrm.com"], ["Sorry, this page is no longer available"], "vulnerable", False),
    ("HatenaBlog", ["hatenablog.com"], ["404 Blog is not found"], "vulnerable", False),
    ("Help Scout", ["helpscoutdocs.com"], ["No settings were found for this company"], "vulnerable", False),
    ("Help Juice", ["helpjuice.com"], ["We could not find what you're looking for"], "vulnerable", False),
    ("SurveySparrow", ["surveysparrow.com"], ["Account not found"], "vulnerable", False),
    ("Uberflip", ["read.uberflip.com"], ["The URL you've accessed does not provide a hub"], "vulnerable", False),
    ("Brightcove", ["bcvp0rtal.com", "brightcovegallery.com", "gallery.video"], ["Error Code: 404"], "vulnerable", False),
    ("Big Cartel", ["bigcartel.com"], ["Oops! We could", "find that page"], "vulnerable", False),
    ("Uptime Robot", ["stats.uptimerobot.com"], ["page not found"], "vulnerable", False),
    ("Readme.io", ["readme.io"], ["Project doesnt exist... yet!"], "vulnerable", False),
    ("Campaign Monitor", ["createsend.com"], ["Trying to access your account?"], "vulnerable", False),
    ("Canny", ["canny.io"], ["Company Not Found"], "vulnerable", False),
    ("Pingdom", ["stats.pingdom.com"], ["Sorry, couldn't find the status page"], "vulnerable", False),
    ("Frontify", ["frontify.com"], ["404 - Page Not Found", "looks like you got lost"], "edge", False),
    ("Smugmug", ["domains.smugmug.com"], [], "vulnerable", True),
    ("Discourse", ["trydiscourse.com"], [], "vulnerable", True),
]

_STATUS_CONFIDENCE = {"vulnerable": "high", "edge": "medium", "notvuln": "low"}

# Body phrases too generic to assert a takeover WITHOUT a DNS/CNAME anchor — they
# match ordinary 404 pages (a default nginx/Apache error would otherwise be
# reported as a high-confidence takeover). Only used to suppress step-3 hits.
_GENERIC_FPS = frozenset({
    "not found", "404 not found", "page not found", "project not found",
    "find that page", "error code: 404",
})


@dataclass
class TakeoverResult:
    host: str
    vulnerable: bool = False
    service: str | None = None
    cname: list[str] = field(default_factory=list)
    matched_fingerprint: str | None = None
    status: str | None = None          # vulnerable | edge | notvuln
    confidence: str | None = None
    dangling_dns: bool = False
    detail: str = "no takeover indicators found"


async def check_takeover(client: HttpClient, host: str, *, scope_check=None) -> TakeoverResult:
    result = TakeoverResult(host=host)

    # Query CNAME FIRST: for a dangling CNAME whose target is NXDOMAIN, the A
    # lookup raises NXDOMAIN and the resolver returns early — so asking for A
    # before CNAME would drop the very record that proves the takeover.
    dns = await resolve(host, rdtypes=("CNAME", "A", "AAAA"), http_client=client)
    cnames = dns.records.get("CNAME", [])
    if dns.canonical_name and dns.canonical_name not in cnames:
        cnames = [dns.canonical_name, *cnames]
    result.cname = cnames
    cname_blob = " ".join(cnames).lower()

    # 1) Match the CNAME target against known providers.
    matched = None
    for name, patterns, fps, status, nxdomain in _FINGERPRINTS:
        if any(p in cname_blob for p in patterns):
            matched = (name, patterns, fps, status, nxdomain)
            break

    # 2) Fetch the site and look for the unclaimed-resource fingerprint.
    body = ""
    for scheme in ("https", "http"):
        r = await client.fetch(f"{scheme}://{host}", follow_redirects=True, timeout=12.0,
                               scope_check=scope_check)
        if r.status is not None:
            body = r.text(limit=100_000)
            break

    if matched:
        name, patterns, fps, status, nxdomain = matched
        result.service = name
        result.status = status
        result.confidence = _STATUS_CONFIDENCE.get(status)
        if nxdomain:
            # Dangling if the record exists but nothing resolves (no A/AAAA).
            if not dns.a and not dns.aaaa:
                result.dangling_dns = True
                result.vulnerable = status != "notvuln"
                result.detail = f"CNAME points at {name} but nothing resolves (dangling DNS) — potential takeover"
            else:
                result.detail = f"CNAME points at {name}; resolves — likely claimed"
        else:
            hit = next((f for f in fps if f.lower() in body.lower()), None)
            if hit:
                result.matched_fingerprint = hit
                result.vulnerable = status != "notvuln"
                result.detail = f"CNAME → {name} and body shows unclaimed-resource fingerprint — potential takeover"
            else:
                result.detail = f"CNAME points at {name} but no unclaimed fingerprint in body"
        return result

    # 3) No CNAME match — a body fingerprint ALONE (no DNS anchor) is only a lead,
    # never a confirmed takeover, and generic 404 phrases are ignored entirely so
    # an ordinary error page is not reported as a takeover.
    for name, _patterns, fps, status, _nxdomain in _FINGERPRINTS:
        hit = next((f for f in fps
                    if f and f.lower() not in _GENERIC_FPS and f.lower() in body.lower()), None)
        if hit:
            result.service = name
            result.matched_fingerprint = hit
            result.status = status
            result.confidence = "low"       # no DNS anchor → weak signal
            result.vulnerable = False        # a lead to verify, not a confirmation
            result.detail = (f"body shows {name} unclaimed-resource fingerprint but no matching "
                             "CNAME — unconfirmed lead, verify DNS/ownership manually")
            return result
    return result
