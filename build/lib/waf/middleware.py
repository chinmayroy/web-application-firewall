import re
import datetime
import logging
from typing import Callable
from django.http import HttpResponseForbidden
from django.utils.timezone import now

logger = logging.getLogger(__name__)  # Log blocked attempts

class WebApplicationFirewall:
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

        self.bad_user_agents = [
            "sqlmap", "nikto", "acunetix", "nessus", "fuzz", "scanner", "bot", "curl", "wget"
        ]

        self.allowed_methods = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}

    def is_suspicious(self, text: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, text):
                return True
        return False

    def log_blocked_attempt(self, request, reason):
        ip = request.META.get("REMOTE_ADDR", "unknown")
        ua = request.META.get("HTTP_USER_AGENT", "unknown")
        logger.warning(f"Blocked IP: {ip} | UA: {ua} | Reason: {reason}")

    def __call__(self, request):
        # ✅ Allow only valid HTTP methods
        if request.method not in self.allowed_methods:
            self.log_blocked_attempt(request, "Invalid HTTP Method")
            return HttpResponseForbidden("403 Forbidden")

        # ✅ Analyze GET and body payload for threats
        payload = ""
        try:
            payload += request.GET.urlencode()
            if hasattr(request, 'body'):
                payload += request.body.decode(errors='ignore')
        except Exception:
            pass

        if self.is_suspicious(payload, self.sql_injection_patterns):
            self.log_blocked_attempt(request, "SQL Injection")
            return HttpResponseForbidden("403 Forbidden")

        if self.is_suspicious(payload, self.xss_patterns):
            self.log_blocked_attempt(request, "XSS Attempt")
            return HttpResponseForbidden("403 Forbidden")

        # ✅ Block bad User-Agent headers
        ua = request.META.get("HTTP_USER_AGENT", "").lower()
        if self.is_suspicious(ua, self.bad_user_agents):
            self.log_blocked_attempt(request, "Bad User-Agent")
            return HttpResponseForbidden("403 Forbidden")

        # ✅ Time-limited access for unauthenticated users
        if not request.user.is_authenticated:
            session = request.session
            now_time = now()

            if "first_seen" not in session:
                session["first_seen"] = now_time.isoformat()
            else:
                try:
                    first_seen = datetime.datetime.fromisoformat(session["first_seen"])
                    if (now_time - first_seen).total_seconds() > 60:
                        self.log_blocked_attempt(request, "Time-limited access expired")
                        return HttpResponseForbidden("403 Forbidden")
                except Exception:
                    self.log_blocked_attempt(request, "Session tampering")
                    return HttpResponseForbidden("403 Forbidden")

        # ✅ Let the request proceed
        return self.get_response(request)
