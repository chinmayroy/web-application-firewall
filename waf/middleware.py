import re
from typing import Callable
from django.http import HttpResponseForbidden

class CustomWAFMiddleware:
    def __init__(self, get_response: Callable):
        self.get_response = get_response

        self.sql_injection_patterns = [
            r"(?i)\bselect\b.*\bfrom\b",
            r"(?i)\binsert\b.*\binto\b",
            r"(?i)\bunion\b.*\bselect\b",
            r"(?i)\bdrop\b.*\btable\b",
            r"(?i)\bupdate\b.*\bset\b",
            r"(?i)\bdelete\b.*\bfrom\b",
        ]

        self.xss_patterns = [
            r"(?i)<script.*?>.*?</script.*?>",
            r"(?i)javascript:",
            r"(?i)<.*?on\w+=.*?>",
            r"(?i)<iframe.*?>.*?</iframe.*?>",
        ]

        self.vulnerable_paths = [
            r"/admin",
            r"/admin.index",
            r"/phpmyadmin",
        ]

        self.bad_user_agents = [
            "sqlmap",
            "nikto",
            "acunetix",
            "nessus",
            "fuzz",
            "scanner",
            "bot",
            "curl",
            "wget",
        ]

        self.allowed_methods = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}

    def is_suspicious(self, text: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, text):
                return True
        return False

    def __call__(self, request):
        if request.method not in self.allowed_methods:
            return HttpResponseForbidden("Forbidden: Invalid HTTP Method")

        payload = ""
        try:
            payload += request.GET.urlencode()
            if hasattr(request, 'body'):
                payload += request.body.decode(errors='ignore')
        except Exception:
            pass

        if self.is_suspicious(payload, self.sql_injection_patterns):
            return HttpResponseForbidden("Forbidden: SQL Injection detected")

        if self.is_suspicious(payload, self.xss_patterns):
            return HttpResponseForbidden("Forbidden: XSS detected")

        path = request.path.lower()
        if self.is_suspicious(path, self.vulnerable_paths):
            return HttpResponseForbidden("Forbidden: Vulnerable path blocked")

        ua = request.META.get("HTTP_USER_AGENT", "").lower()
        if self.is_suspicious(ua, self.bad_user_agents):
            return HttpResponseForbidden("Forbidden: Malicious User-Agent detected")

        return self.get_response(request)
