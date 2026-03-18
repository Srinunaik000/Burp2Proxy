import re
from mitmproxy import http

class SecurityLinter:
    """
    Passive security linter that analyzes HTTP flows for common vulnerabilities
    and misconfigurations.
    """

    # Common security headers to check for
    SECURITY_HEADERS = {
        "Content-Security-Policy": "Missing Content-Security-Policy (CSP) header. CSP helps prevent XSS and data injection attacks.",
        "X-Frame-Options": "Missing X-Frame-Options header. This makes the site vulnerable to clickjacking.",
        "X-Content-Type-Options": "Missing X-Content-Type-Options: nosniff header. This prevents MIME-sniffing attacks.",
        "Strict-Transport-Security": "Missing Strict-Transport-Security (HSTS) header. This ensures connections use HTTPS.",
        "Referrer-Policy": "Missing Referrer-Policy header. This controls how much referrer information is shared.",
        "Permissions-Policy": "Missing Permissions-Policy header. This allows you to control which browser features can be used."
    }

    # Sensitive patterns to look for in response bodies
    SENSITIVE_PATTERNS = {
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Generic API Key": r"[a|A][p|P][i|I]_?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
        "Generic Secret": r"[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
        "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Access Key": r"['|\"][0-9a-zA-Z\/+]{40}['|\"]",
        "Authorization Header (Bearer)": r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
        "Private Key": r"-----BEGIN PRIVATE KEY-----",
        "Firebase URL": r"https://.*\.firebaseio\.com",
        "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
        "Possible Password/Secret in URL": r"(?:password|passwd|pwd|secret|token|apikey)=([^&^#]+)"
    }

    @staticmethod
    def run_checks(flow: http.HTTPFlow):
        """Runs all passive security checks on the given flow."""
        issues = []
        
        if not flow.response:
            return issues

        # 1. Check for missing security headers (only for HTML responses)
        content_type = flow.response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            for header, description in SecurityLinter.SECURITY_HEADERS.items():
                if header not in flow.response.headers:
                    issues.append({
                        "title": f"Missing {header}",
                        "severity": "Low",
                        "description": description,
                        "type": "Header"
                    })

        # 2. Check for Information Disclosure in headers
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]
        for header in disclosure_headers:
            if header in flow.response.headers:
                issues.append({
                    "title": f"Information Disclosure: {header}",
                    "severity": "Info",
                    "description": f"The '{header}' header is present ({flow.response.headers[header]}). It may reveal server technology and versions.",
                    "type": "Disclosure"
                })

        # 3. Check for Insecure Cookies
        for cookie_name, cookie_value in flow.response.cookies.items():
            cookie_params = cookie_value[1]
            cookie_issues = []
            
            if "httponly" not in [k.lower() for k in cookie_params.keys()]:
                cookie_issues.append("HttpOnly flag is missing")
            
            if "secure" not in [k.lower() for k in cookie_params.keys()] and flow.request.scheme == "https":
                cookie_issues.append("Secure flag is missing")
                
            if "samesite" not in [k.lower() for k in cookie_params.keys()]:
                cookie_issues.append("SameSite attribute is missing")

            if cookie_issues:
                issues.append({
                    "title": f"Insecure Cookie: {cookie_name}",
                    "severity": "Low",
                    "description": f"Cookie '{cookie_name}' has the following issues: {', '.join(cookie_issues)}.",
                    "type": "Cookie"
                })

        # 4. Check for Sensitive Information in Response Body
        resp_text = ""
        try:
            resp_text = flow.response.text or ""
        except:
            # Fallback for non-utf8 or binary that might still have text strings
            resp_text = flow.response.get_content(strict=False).decode('latin-1', errors='ignore')

        if resp_text:
            for name, pattern in SecurityLinter.SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, resp_text)
                if matches:
                    issues.append({
                        "title": f"Sensitive Information: {name}",
                        "severity": "Medium",
                        "description": f"Possible {name} found in the response body.",
                        "type": "Sensitive Data",
                        "matches": list(set(matches))[:5] # Limit to first 5 unique matches
                    })

        # 5. Check for PII (Simple patterns for Email, IP, etc.)
        pii_patterns = {
            "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "IPv4 Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        }
        
        # Only scan text-based responses for PII
        if resp_text and any(t in content_type for t in ["text", "json", "javascript", "xml"]):
            for name, pattern in pii_patterns.items():
                matches = re.findall(pattern, resp_text)
                if matches:
                    # Filter out common false positives for IPs (like 127.0.0.1 or 0.0.0.0)
                    if name == "IPv4 Address":
                        matches = [m for m in matches if not m.startswith(("127.", "0.", "192.168.", "10."))]
                    
                    if matches:
                        issues.append({
                            "title": f"Possible PII: {name}",
                            "severity": "Low",
                            "description": f"Possible {name} found in the response body.",
                            "type": "PII",
                            "matches": list(set(matches))[:5]
                        })

        return issues
