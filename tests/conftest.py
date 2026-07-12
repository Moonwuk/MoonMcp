import http.server
import socketserver
import threading

import pytest

from moonmcp import server as srv
from moonmcp.context import build_context

# A deliberately-vulnerable SPA: it deep-merges location.search + location.hash into
# an object via bracket/dot paths, so a __proto__/constructor path pollutes
# Object.prototype in the page's JS realm (client-side prototype pollution).
_CSPP_VULN = rb"""<!doctype html><html><head><title>CSPP</title></head><body>cspp app
<script>
function setPath(o,p,v){var ks=p.split(/[\[\]\.]+/).filter(Boolean);var c=o;
for(var i=0;i<ks.length-1;i++){if(c[ks[i]]===undefined)c[ks[i]]={};c=c[ks[i]];}
c[ks[ks.length-1]]=v;}
function parse(s){var o={};(s||'').replace(/^[?#]/,'').split('&').forEach(function(p){
if(!p)return;var kv=p.split('=');setPath(o,decodeURIComponent(kv[0]),decodeURIComponent(kv[1]||''));});
return o;}
parse(location.search);parse(location.hash);
</script></body></html>"""

# The hardened twin: it refuses the dangerous keys, so no pollution occurs.
_CSPP_SAFE = rb"""<!doctype html><html><head><title>CSPP</title></head><body>cspp safe
<script>
function setPath(o,p,v){var ks=p.split(/[\[\]\.]+/).filter(Boolean);
for(var i=0;i<ks.length;i++){if(ks[i]==='__proto__'||ks[i]==='constructor'||ks[i]==='prototype')return;}
var c=o;for(var i=0;i<ks.length-1;i++){if(c[ks[i]]===undefined)c[ks[i]]={};c=c[ks[i]];}
c[ks[ks.length-1]]=v;}
function parse(s){var o={};(s||'').replace(/^[?#]/,'').split('&').forEach(function(p){
if(!p)return;var kv=p.split('=');setPath(o,decodeURIComponent(kv[0]),decodeURIComponent(kv[1]||''));});
return o;}
parse(location.search);parse(location.hash);
</script></body></html>"""


# The one SignatureValue the SAML test fixtures treat as "genuinely signed" --
# real XML-DSig crypto is out of scope for a zero-dependency test harness, so
# this constant stands in for "the signature verifies", exactly like the real
# saml_xsw_probe fixture's SAMLResponse carries it unmodified while
# corrupt_signature() flips one character to produce an "invalid" twin.
_SAML_VALID_SIG = "ZmFrZXNpZ25hdHVyZXZhbHVlPT0="
_SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


class _Handler(http.server.BaseHTTPRequestHandler):
    _lb = 0    # /lb backend rotation counter
    _rl = 0    # /rl rate-limit counter
    _stored = ""   # /store last-written value, re-rendered by /render (second-order)

    def log_message(self, *args):  # silence
        pass

    def _saml_reply(self, raw: bytes, safe: bool):
        import base64
        from urllib.parse import parse_qs
        from xml.etree import ElementTree as ET
        fields = parse_qs(raw.decode("utf-8", "replace"))
        b64 = (fields.get("SAMLResponse") or [""])[0]
        try:
            xml_text = base64.b64decode(b64).decode("utf-8", "replace")
            root = ET.fromstring(xml_text)
        except Exception:
            body = b"<html>bad request</html>"
            self.send_response(400)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        sig = root.find(".//ds:Signature", _SAML_NS)
        sig_val = sig.find("ds:SignatureValue", _SAML_NS) if sig is not None else None
        if sig_val is None or (sig_val.text or "").strip() != _SAML_VALID_SIG:
            body = b"<html>signature invalid</html>"
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if safe:
            # SAFE: resolves identity from the assertion whose ID matches what
            # the Signature's Reference actually covers, wherever it sits.
            ref = sig.find("ds:SignedInfo/ds:Reference", _SAML_NS)
            ref_id = (ref.get("URI") or "").lstrip("#") if ref is not None else None
            assertion = next((el for el in root.iter()
                              if el.tag.endswith("}Assertion") and el.get("ID") == ref_id), None)
        else:
            # VULNERABLE: naive "first direct-child Assertion" identity read --
            # ignores which assertion the Signature Reference actually covers.
            assertion = root.find("saml:Assertion", _SAML_NS)
        nameid = assertion.find(".//saml:Subject/saml:NameID", _SAML_NS) if assertion is not None else None
        identity = nameid.text if nameid is not None else "unknown"
        body = f"<html>Welcome, {identity}</html>".encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _nosqli_reply(self, text: str, ctype: str):
        # DELIBERATELY VULNERABLE login: a plain scalar `user` is denied (401), but
        # an operator OBJECT ($ne/$gt/$nin, or $where returning true) bypasses auth
        # (200 + a session cookie + a longer "records" body). $where:false stays 401,
        # giving the boolean oracle its differential.
        from urllib.parse import parse_qs
        operator = where_false = False
        if "json" in ctype:
            import json as _json
            try:
                v = _json.loads(text).get("user")
            except Exception:
                v = None
            if isinstance(v, dict):
                where_false = v.get("$where") == "return false"
                operator = not where_false
        else:
            operator = any("[$" in k for k in parse_qs(text))
        if operator and not where_false:
            body = (b"<html>welcome admin! records: alice bob carol dave "
                    b"erin frank grace heidi ivan</html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=itsme; Path=/; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html>invalid credentials</html>"
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _pd_write(self, code: int, val: str):
        body = f"<html>p={val}</html>".encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parserdiff(self, raw: bytes, ctype: str, safe: bool):
        # DELIBERATELY VULNERABLE (unless safe): a lax parser that decodes UTF-7 form
        # bodies and accepts JSON comments / trailing commas / a leading BOM and
        # bare-LF multipart — forms a STANDARD parser rejects — while still rejecting
        # blatantly-broken input. The safe twin is a *standard* parser: it accepts
        # only RFC-permitted quirks (duplicate keys/fields, last-wins) and rejects the
        # rest, so the tolerance lanes correctly stay silent on it.
        import json as _json
        import re
        from urllib.parse import parse_qs
        txt = raw.decode("utf-8", "replace")
        low = ctype.lower()
        if "multipart" in low:
            m = re.search(r"boundary=([^\s;]+)", ctype)
            bnd = m.group(1) if m else ""
            if not bnd or ("--" + bnd) not in txt:          # declared boundary absent → malformed
                return self._pd_write(400, "bad")
            if safe and ("--" + bnd + "\r\n") not in txt:   # strict: CRLF required → reject bare-LF
                return self._pd_write(400, "lf")
            vals = re.findall(r'name="p"\r?\n\r?\n(.*?)(?=\r?\n--)', txt, re.S)
            if not vals:
                return self._pd_write(400, "bad")
            return self._pd_write(200, vals[-1])            # last field wins (both routes)
        if "json" in low:
            body = txt if safe else txt.lstrip("\ufeff")  # lax: silently skip a leading BOM
            if not safe:
                body = re.sub(r"//[^\n]*", "", body)        # strip // comments
                body = re.sub(r",(\s*[}\]])", r"\1", body)  # strip trailing commas
            try:
                v = str(_json.loads(body).get("p", ""))     # duplicate keys → last wins (both)
            except Exception:
                return self._pd_write(400, "bad")
            return self._pd_write(200, v)
        # urlencoded form (utf7 lane + baseline)
        val = (parse_qs(txt).get("p") or [""])[0]
        if not safe and "utf-7" in low:
            try:
                val = val.encode("latin-1", "replace").decode("utf-7")
            except Exception:
                pass
        return self._pd_write(200, val)

    def _parserdiff_get(self, safe: bool):
        # GET lane: overlong-UTF-8 normalisation in the query (vulnerable) vs a
        # strict decode that leaves the overlong bytes as replacement chars (safe).
        import re
        from urllib.parse import unquote_to_bytes
        rawq = self.path.split("?", 1)[1] if "?" in self.path else ""
        m = re.search(r"(?:^|&)p=([^&]*)", rawq)
        bs = unquote_to_bytes(m.group(1)) if m else b""
        if safe:
            val = bs.decode("utf-8", "replace")
        else:
            out = bytearray()
            i = 0
            while i < len(bs):
                b = bs[i]
                if b in (0xC0, 0xC1) and i + 1 < len(bs) and 0x80 <= bs[i + 1] <= 0xBF:
                    out.append((((b & 0x1F) << 6) | (bs[i + 1] & 0x3F)) & 0x7F)
                    i += 2
                else:
                    out.append(b)
                    i += 1
            val = out.decode("latin-1", "replace")
        return self._pd_write(200, val)

    def do_POST(self):
        # drain the request body so the socket stays clean
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.startswith("/saml-acs-vuln"):
            self._saml_reply(raw, safe=False)
            return
        if self.path.startswith("/saml-acs-safe"):
            self._saml_reply(raw, safe=True)
            return
        if self.path.startswith("/store"):
            # Phase 1 of a second-order flow: store the written value (safely) so a
            # later /render call re-uses it in a query (the vulnerable sink).
            from urllib.parse import parse_qs
            ctype = self.headers.get("Content-Type", "")
            if "json" in ctype:
                import json as _json
                try:
                    v = str(_json.loads(raw.decode("utf-8", "replace")).get("comment", ""))
                except Exception:
                    v = ""
            else:
                v = (parse_qs(raw.decode("utf-8", "replace")).get("comment") or [""])[0]
            type(self)._stored = v
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"saved")
            return
        if self.path.startswith("/xxe-oob"):
            # VULNERABLE: a non-validating XML parser that dereferences a SYSTEM
            # external entity (simulated by actually fetching any SYSTEM "http(s)://..."
            # URL found in the raw body -- proving the parser resolved the entity).
            import re as _re
            text = raw.decode("utf-8", "replace")
            mm = _re.search(r'SYSTEM\s+"(https?://[^"]+)"', text)
            if mm:
                try:
                    import urllib.request
                    urllib.request.urlopen(mm.group(1), timeout=2).read(64)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<result>ok</result>")
            return
        if self.path.startswith("/xxe-safe"):
            # SAFE twin: a hardened parser that never dereferences external entities
            # regardless of what the body contains.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<result>ok</result>")
            return
        if self.path.startswith("/nosqli-safe"):
            # NOT vulnerable: identical 200 regardless of operator vs scalar.
            body = b"<html>login page</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/fastjson"):
            # DELIBERATELY VULNERABLE: "deserializes" the @type body by fetching the
            # URL it carries (simulates java.net.URL autoType → outbound lookup).
            import re
            mm = re.search(r"https?://[^\s\"'}\]]+", raw.decode("utf-8", "replace"))
            if mm:
                try:
                    import urllib.request
                    urllib.request.urlopen(mm.group(0), timeout=2).read(64)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/nosqli"):
            self._nosqli_reply(raw.decode("utf-8", "replace"),
                               self.headers.get("Content-Type", ""))
            return
        if self.path.startswith("/gqlnosqli"):
            import json as _json
            try:
                v = _json.loads(raw.decode("utf-8", "replace")).get("variables", {}).get("moon")
            except Exception:
                v = None
            obj = isinstance(v, dict)
            p = self.path
            code, cookie = 200, None
            if p.startswith("/gqlnosqli-safe"):
                # strictly-typed String variable: a spec-compliant server returns HTTP 400
                # for the variable-coercion error (must NOT be scored as an injection).
                if obj:
                    code = 400
                    body = (b'{"data":null,"errors":[{"message":"Variable \\"$moon\\" got invalid '
                            b'value {}; Expected type String to be a string."}]}')
                else:
                    body = b'{"data":{"login":null}}'
            elif p.startswith("/gqlnosqli-big"):
                # winning body is LARGER than the 50k slice → the data flag must come from
                # the full body, not a truncated read.
                if obj:
                    rows = ",".join(
                        f'{{"id":{i},"email":"user{i}@example.com","name":"User Number {i}"}}'
                        for i in range(1500))
                    body = ('{"data":{"users":[' + rows + ']}}').encode()
                else:
                    body = b'{"data":{"users":[]}}'
            elif p.startswith("/gqlnosqli-cookie"):
                # auth flip signalled ONLY by Set-Cookie; the body shape is unchanged.
                if obj:
                    body, cookie = b'{"data":{"login":{"ok":true}}}', "session=abc123; Path=/; HttpOnly"
                else:
                    body = b'{"data":{"login":{"ok":false}}}'
            else:
                # DELIBERATELY VULNERABLE: the object flows into find() -> auth bypass
                if obj:
                    body = (b'{"data":{"login":{"id":1,"role":"admin",'
                            b'"token":"eyJhbGciOiJIUzI1NiJ9.moonadmin.sig"}}}')
                else:
                    body = b'{"data":{"login":null}}'   # scalar control: auth fails
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/parserdiff-safe"):
            self._parserdiff(raw, self.headers.get("Content-Type", ""), safe=True)
            return
        if self.path.startswith("/parserdiff"):
            self._parserdiff(raw, self.headers.get("Content-Type", ""), safe=False)
            return
        self.send_response(404)
        self.end_headers()

    def _ws_upgrade(self, strict):
        # Minimal RFC 6455 server side for the ws_probe tests. `strict` validates the
        # Origin (rejects a foreign one → no CSWSH); the lenient endpoint accepts any
        # Origin (CSWSH-vulnerable). Echoes one frame back if the client sends one.
        from moonmcp.web import websocket as _ws
        key = self.headers.get("Sec-WebSocket-Key")
        upgrade = (self.headers.get("Upgrade") or "").lower()
        origin = self.headers.get("Origin")
        if "websocket" not in upgrade or not key:
            self.send_response(400)
            self.end_headers()
            return
        if strict and origin and not origin.startswith(("http://127.0.0.1", "https://127.0.0.1")):
            self.send_response(403)  # foreign Origin refused
            self.end_headers()
            return
        resp = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Accept: {_ws.accept_value(key)}\r\n\r\n")
        self.wfile.write(resp.encode("latin-1"))
        self.wfile.flush()
        try:  # optional: echo one client frame back (unmasked), else EOF/timeout → return
            self.connection.settimeout(2.0)
            hdr = self.rfile.read(2)
            if len(hdr) < 2:
                return
            ln = hdr[1] & 0x7F
            masked = hdr[1] & 0x80
            rest = self.rfile.read((4 if masked else 0) + ln)
            _op, payload, _c = _ws.decode_frame(hdr + rest)
            if payload:
                self.wfile.write(bytes([0x81, len(payload)]) + payload)
                self.wfile.flush()
        except OSError:
            return

    def do_GET(self):
        if self.path == "/ws":
            return self._ws_upgrade(strict=False)
        if self.path == "/ws-strict":
            return self._ws_upgrade(strict=True)
        if self.path == "/echo":
            # Echo the request headers back as JSON (used to verify auth context).
            import json as _json
            payload = _json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/reflect"):
            # Reflect the value of ?name= into the body (reflected-param signal) and
            # add a chunk of text when ?admin is present (length-change signal).
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            body = b"<html>base"
            if "name" in qs:
                body += b" name=" + qs["name"][0].encode("utf-8", "replace")
            if "admin" in qs:
                body += b" ADMIN-PANEL-VISIBLE-EXTRA-CONTENT-BLOCK-XYZ"
            body += b"</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/ssti"):
            # DELIBERATELY VULNERABLE (eval target): "renders" a Jinja2-style
            # {{7331*7}} expression by echoing the evaluated result.
            from urllib.parse import parse_qs, urlparse
            name = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
            out = name.replace("{{7331*7}}", "51317") if "{{" in name else name
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>hello " + out.encode("utf-8", "replace") + b"</html>")
            return
        if self.path.startswith("/sqli?") or self.path == "/sqli":
            # DELIBERATELY VULNERABLE: a single quote yields a MySQL error; the
            # boolean pair yields different-length bodies.
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            if "'" in q and "'1'='1" not in q and "'1'='2" not in q:
                body = b"Database error: You have an error in your SQL syntax; check the MySQL manual"
            elif "'1'='1" in q:
                body = b"<html>results: alice bob carol dave erin frank grace</html>"
            else:
                body = b"<html>results:</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/sqli-order"):
            # VULNERABLE ORDER BY: the injected CASE expression is evaluated as a
            # sort key, so WHEN 1=1 vs WHEN 1=2 yields different-length row sets.
            from urllib.parse import parse_qs, urlparse
            s = (parse_qs(urlparse(self.path).query).get("sort") or [""])[0]
            if "WHEN 1=1" in s:
                body = b"<html>rows: alice bob carol dave erin frank grace</html>"
            elif "WHEN 1=2" in s:
                body = b"<html>rows: grace</html>"
            else:
                body = b"<html>rows: default</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/sqli-time"):
            # VULNERABLE time-based: honours SLEEP/PG_SLEEP/WAITFOR delays.
            import re
            import time as _time
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            mt = re.search(r"(?:SLEEP|PG_SLEEP)\(([\d.]+)\)", q, re.I) or re.search(r"0:0:([\d.]+)", q)
            if mt:
                try:
                    _time.sleep(min(float(mt.group(1)), 3.0))
                except ValueError:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/cmdi-time"):
            # VULNERABLE time-based command injection: any separator (; | && & ` $())
            # feeding into a shell honours `sleep N` — the query string carries the
            # raw payload (test-only convenience; real targets take it via a param).
            import re
            import time as _time
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            mt = re.search(r"sleep (\d+(?:\.\d+)?)", q, re.I)
            if mt:
                try:
                    _time.sleep(min(float(mt.group(1)), 3.0))
                except ValueError:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/cmdi-safe"):
            # SAFE twin: never sleeps regardless of the injected separator/payload.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/cmdi-oob"):
            # VULNERABLE OOB command injection: a `curl <url>` in the payload is
            # actually fetched server-side (simulating shell execution reaching out).
            import re
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            mm = re.search(r"curl (https?://\S+)", q)
            if mm:
                try:
                    import urllib.request
                    urllib.request.urlopen(mm.group(1), timeout=2).read(64)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/lfi-vuln"):
            # VULNERABLE: fully decodes the param (simulating an edge layer that
            # decodes once and a backend framework that decodes again — the
            # double-encoded-bypass scenario) and serves the traversed file's
            # content when the resolved path matches a known target file.
            import urllib.parse as _up
            from urllib.parse import parse_qs, urlparse
            raw_q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            decoded = _up.unquote(raw_q)  # a 2nd decode pass catches the double-encoded payload
            low = decoded.lower().split("\x00")[0]  # a null byte truncates the path like a real OS call
            if "etc/passwd" in low or "etc\\passwd" in low:
                body = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            elif "win.ini" in low:
                body = b"; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n"
            else:
                body = b"<html>not found</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/lfi-safe"):
            # SAFE twin: never returns file content regardless of the payload.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")
            return
        if self.path.startswith("/interp-vuln"):
            # VULNERABLE (highly interpretive): simulates escape/quote stripping,
            # NUL-byte truncation, path-segment collapsing, and template-brace
            # stripping, so every marker independently shows "interpreted" -- a
            # synthetic worst case, not a claim any single real backend does all 5.
            from urllib.parse import parse_qs, urlparse
            v = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            if v.endswith("\\") or v.endswith("'"):
                v = v[:-1]
            if "\x00" in v:
                v = v.split("\x00", 1)[0]
            v = v.replace("/./", "/").replace("{}", "")
            body = ("<html>" + v + "</html>").encode("utf-8", "replace")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/interp-safe"):
            # SAFE (opaque storage): echoes the value byte-for-byte -- no
            # interpretation of any marker.
            from urllib.parse import parse_qs, urlparse
            v = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            body = ("<html>" + v + "</html>").encode("utf-8", "replace")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/sqli-mb"):
            # VULNERABLE charset mismatch: a multibyte lead byte + quote breaks out
            # of the (naive addslashes) escaping, so it errors where plain %27 doesn't.
            p = self.path
            if any(t in p for t in ("%bf%27", "%82%27", "%a1%27")):
                body = b"Database error: You have an error in your SQL syntax; check the MySQL manual"
            else:
                body = b"<html>ok</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/sqli-waf"):
            # A naive WAF blocks the classic tautology but not the JSON-operator form.
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            if "'1'='1" in q or "'1'='2" in q:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"blocked by WAF")
                return
            if "jsonb" in q and "@>" in q:
                is_true = '@> \'{"a":1}\'' in q
                body = b"<html>rows: a b c d e f g h i</html>" if is_true else b"<html>rows:</html>"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")
            return
        if self.path.startswith("/sqli-oob"):
            # VULNERABLE OOB: the injected UTL_HTTP URL is fetched server-side.
            import re
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            mm = re.search(r"https?://[^\s')]+", q)
            if mm:
                try:
                    import urllib.request
                    urllib.request.urlopen(mm.group(0), timeout=2).read(64)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/sqli-hdr"):
            # VULNERABLE header SQLi: the User-Agent value flows into a query.
            ua = self.headers.get("User-Agent", "")
            if "'" in ua and "'1'='1" not in ua and "'1'='2" not in ua:
                body = b"Database error: You have an error in your SQL syntax; check the MySQL manual"
            elif "'1'='1" in ua:
                body = b"<html>rows: alice bob carol dave erin</html>"
            else:
                body = b"<html>rows:</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/render"):
            # Phase 2 (VULNERABLE sink): re-uses the /store'd value in a query, so a
            # stored quote errors, a stored boolean twin diverges, and a stored OOB
            # payload's URL is fetched server-side — all AWAY from the write endpoint.
            v = type(self)._stored
            import re
            mm = re.search(r"https?://[^\s')]+", v)
            if mm:
                try:
                    import urllib.request
                    urllib.request.urlopen(mm.group(0), timeout=2).read(64)
                except Exception:
                    pass
            vb = v.encode("utf-8", "replace")
            if "'" in v and "AND '1'='1" not in v and "AND '1'='2" not in v:
                body = (b"Database error: You have an error in your SQL syntax; check the MySQL "
                        b"manual near '" + vb[:40] + b"'")
            elif "AND '1'='1" in v:
                body = b"<html>comment " + vb + b" -> rows: a b c d e f g h</html>"
            elif "AND '1'='2" in v:
                body = b"<html>comment " + vb + b" -> rows:</html>"
            else:
                body = b"<html>comment: " + vb + b"</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/fbapp":
            # App page whose firebaseConfig.databaseURL points at THIS local server,
            # so the derived RTDB backend is in-scope (127.0.0.1) for the test.
            host = self.headers.get("Host", "127.0.0.1")
            body = (b"<html><script>var firebaseConfig={apiKey:'AIzaFakeKey',"
                    b"projectId:'demo-proj',databaseURL:'http://" + host.encode() + b"'};"
                    b"</script></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/fbapp-noconfig":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>no firebase here</html>")
            return
        if self.path.startswith("/.json"):
            # DELIBERATELY OPEN Firebase RTDB: shallow read returns data with no auth.
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"users":true,"settings":true}')
            return
        if self.path.startswith("/rest/v1/"):
            # DELIBERATELY RLS-OFF Supabase (PostgREST): schema lists tables; 'users'
            # returns a row (RLS off), others return [] (RLS on).
            from urllib.parse import urlparse
            p = urlparse(self.path).path
            if p == "/rest/v1/":
                body = b'{"definitions":{"users":{},"profiles":{}},"paths":{}}'
            else:
                table = p[len("/rest/v1/"):]
                body = b'[{"id":1,"email":"redactme"}]' if table == "users" else b"[]"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/orm-safe"):
            # NOT vulnerable: ignores injected ORM lookups → constant result set.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>users: alice bob carol dave erin frank</html>")
            return
        if self.path.startswith("/orm-search"):
            # DELIBERATELY VULNERABLE: an injected ORM lookup (Django __startswith,
            # Prisma [startsWith], Ransack _start) is applied as a filter — empty
            # prefix matches all rows, an unlikely prefix matches none.
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query, keep_blank_values=True)
            injected = None
            for k, vals in qs.items():
                kl = k.lower()
                if kl.endswith("__startswith") or "startswith" in kl or k.endswith("_start]") or k.endswith("_start"):
                    injected = vals[0]
                    break
            if injected is None or injected == "":
                body = b"<html>users: alice bob carol dave erin frank grace heidi ivan</html>"
            else:
                body = b"<html>users:</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/ssrf-proto"):
            # DELIBERATELY VULNERABLE: fetches the injected ?url= server-side and
            # reflects whether the internal target was reachable (distinct body length).
            from urllib.parse import parse_qs, urlparse
            u = (parse_qs(urlparse(self.path).query).get("url") or [""])[0]
            reachable = False
            if u.startswith(("http://", "https://")):
                try:
                    import urllib.request
                    urllib.request.urlopen(u, timeout=1).read(16)
                    reachable = True
                except Exception:
                    reachable = False
            body = b"internal-service-reachable-marker" if reachable else b"refused"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/ssrf"):
            # DELIBERATELY VULNERABLE: fetches the ?url= param server-side.
            from urllib.parse import parse_qs, urlparse
            url = (parse_qs(urlparse(self.path).query).get("url") or [""])[0]
            if url.startswith("http://") or url.startswith("https://"):
                try:
                    import urllib.request
                    urllib.request.urlopen(url, timeout=2).read(64)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>fetched</html>")
            return
        if self.path.startswith("/cache"):
            # DELIBERATELY VULNERABLE: reflects the unkeyed X-Forwarded-Host header
            # and marks the response cacheable.
            xfh = self.headers.get("X-Forwarded-Host", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "public, max-age=60")
            self.end_headers()
            self.wfile.write(b"<html><link href='//" + xfh.encode("utf-8", "replace")
                             + b"/style.css'></html>")
            return
        if self.path.startswith("/lb"):
            # Two backends behind an LB with a Server-version mismatch (patch drift).
            type(self)._lb += 1
            if type(self)._lb % 2 == 0:
                server_hdr, backend = "nginx/1.24.0", "node-a"
            else:
                server_hdr, backend = "nginx/1.25.1", "node-b"
            # send_response_only avoids the handler's default Server header so our
            # injected version is the authoritative one.
            self.send_response_only(200)
            self.send_header("Server", server_hdr)
            self.send_header("X-Backend-Server", backend)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/vhost"):
            # Serves the same app for any Host AND reflects it into a link.
            host = self.headers.get("Host", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><a href='//" + host.encode("utf-8", "replace")
                             + b"/next'>go</a></html>")
            return
        if self.path.startswith("/edge"):
            # Looks like it sits behind Cloudflare with a cache layer.
            self.send_response_only(200)
            self.send_header("Server", "cloudflare")
            self.send_header("CF-RAY", "8a1b2c3d4e5f-FRA")
            self.send_header("CF-Cache-Status", "HIT")
            self.send_header("Via", "1.1 varnish, 1.1 cloudflare")
            self.send_header("Age", "42")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/rl"):
            # Rate limit that keys on the (spoofable) X-Forwarded-For header.
            if self.headers.get("X-Forwarded-For"):
                type(self)._rl = 0  # per-IP bypass
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            type(self)._rl += 1
            if type(self)._rl > 5:
                self.send_response(429)
                self.send_header("Retry-After", "30")
                self.end_headers()
                self.wfile.write(b"slow down")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/spa":
            body = (b"<html><head><script src=\"/static/app.js\"></script></head>"
                    b"<body><script>fetch('/api/v2/users');var u='/api/v2/orders';"
                    b"</script></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/article":
            # A rich page for the OSINT reader: title, meta description, boilerplate
            # to strip (script/style/nav), readable prose, and outbound links.
            body = (b"<!doctype html><html><head><title>CVE-2021-44228 Analysis</title>"
                    b"<meta name=\"description\" content=\"Log4Shell deep dive\">"
                    b"<style>.x{color:red}</style>"
                    b"<script>var tracker='should-not-appear';</script></head>"
                    b"<body><nav><a href=\"/home\">Home</a></nav>"
                    b"<h1>Log4Shell</h1>"
                    b"<p>The JNDI lookup enabled remote code execution.</p>"
                    b"<p>See <a href=\"https://nvd.nist.gov/vuln/detail/CVE-2021-44228\">the NVD entry</a>"
                    b" for details.</p>"
                    b"<script>console.log('nope');</script></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/static/app.js":
            body = (b"const base='/api/internal/config';"
                    b"fetch('/api/v1/admin/users?id=1');\n"
                    b"//# sourceMappingURL=app.js.map\n")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/openapi.json":
            import json as _json
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.2.3"},
                "servers": [{"url": "https://api.demo.test/v1"}],
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "security": [{"bearer": []}],
                "paths": {
                    "/users/{id}": {
                        "get": {"operationId": "getUser",
                                "parameters": [{"name": "id", "in": "path", "required": True,
                                                "schema": {"type": "integer"}}]},
                        "delete": {"operationId": "delUser", "security": []},
                    },
                    "/public/health": {"get": {"operationId": "health", "security": []}},
                },
            }
            payload = _json.dumps(spec).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/app":
            # A tiny interactive page: fill #q, click #go → writes #out + localStorage.
            body = (
                b"<title>App</title><input id='q'>"
                b"<button id='go' onclick=\"document.getElementById('out').innerText="
                b"'clicked:'+document.getElementById('q').value;"
                b"localStorage.setItem('token','t0ken');console.log('go-clicked')\">Go</button>"
                b"<div id='out'></div>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\nDisallow: /secret\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/only-secret":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/redirect-out":
            # Redirect to an out-of-scope host — MoonMCP must refuse to follow.
            self.send_response(302)
            self.send_header("Location", "http://evil.example/pwned")
            self.end_headers()
            return
        if self.path in ("/r1", "/r2"):
            # A same-host redirect chain: /r1 -> /r2 -> / (all in scope).
            self.send_response(302)
            self.send_header("Location", "/r2" if self.path == "/r1" else "/")
            self.end_headers()
            return
        if self.path.startswith("/bucket"):
            # Mock cloud-bucket endpoint: 200 for 'acme-backup', 403 for
            # 'acme-private', 404 otherwise — to test status classification.
            from urllib.parse import parse_qs, urlparse
            name = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
            code = 200 if name == "acme-backup" else 403 if name == "acme-private" else 404
            self.send_response(code)
            self.end_headers()
            return
        if self.path.startswith("/oast-poll"):
            # A mock OAST poll endpoint returning one interaction.
            from urllib.parse import parse_qs, urlparse
            tok = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
            payload = ('{"interactions":[{"protocol":"http","from":"203.0.113.9","token":"'
                       + tok + '"}]}').encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/cspp-safe") or self.path.startswith("/cspp"):
            body = _CSPP_SAFE if self.path.startswith("/cspp-safe") else _CSPP_VULN
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/parserdiff-safe"):
            self._parserdiff_get(safe=True)
            return
        if self.path.startswith("/parserdiff"):
            self._parserdiff_get(safe=False)
            return
        if self.path.rstrip("/") in ("/admin",):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden")
            return
        if self.path == "/missing":
            self.send_response(404)
            self.end_headers()
            return
        body = b"<html><head><title>Local</title></head><body>hello react-root</body></html>"
        self.send_response(200)
        self.send_header("Server", "nginx/1.25.1")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Set-Cookie", "sid=1; Path=/")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def local_server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", port
    finally:
        httpd.shutdown()


@pytest.fixture()
def fresh_context(monkeypatch):
    """Give the server module a fresh, in-scope context for 127.0.0.1."""

    ctx = build_context()
    # Local-server tests target 127.0.0.1, so disable the private-IP SSRF guard.
    ctx.scope.block_private = False
    ctx.scope.add("127.0.0.1")
    monkeypatch.setattr(srv, "_CTX", ctx)
    return ctx
