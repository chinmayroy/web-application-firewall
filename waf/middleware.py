import re
import datetime
import logging
from typing import Callable
from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.conf import settings

logger = logging.getLogger(__name__)

VALID_API_KEY = settings.API_ACCESS_KEY

class WebApplicationFirewall:
    def __init__(self, get_response: Callable):
        self.get_response = get_response

        # Patterns to detect SQL injection
        self.sql_patterns = [
            r"(?i)\bselect\b.*\bfrom\b",
            r"(?i)\binsert\b.*\binto\b",
            r"(?i)\bunion\b.*\bselect\b",
            r"(?i)\bdrop\b.*\btable\b",
            r"(?i)\bupdate\b.*\bset\b",
            r"(?i)\bdelete\b.*\bfrom\b",
        ]

        # Patterns to detect XSS
        self.xss_patterns = [
            r"(?i)<script.*?>.*?</script.*?>",
            r"(?i)javascript:",
            r"(?i)<.*?on\w+=.*?>",
            r"(?i)<iframe.*?>.*?</iframe.*?>",
        ]

        # Known malicious user agents
        self.blocked_agents = [
            "sqlmap", "nikto", "acunetix", "nessus", "fuzz", "scanner", "bot", "curl", "wget"
        ]

        # Only allow common HTTP methods
        self.allowed_methods = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}

    def is_suspicious(self, text: str, patterns: list[str]) -> bool:
        return any(re.search(pattern, text) for pattern in patterns)

    def log_block(self, request, reason):
        ip = request.META.get("REMOTE_ADDR", "unknown")
        ua = request.META.get("HTTP_USER_AGENT", "unknown")
        logger.warning(f"Blocked: IP={ip} | UA={ua} | Reason={reason}")

    def __call__(self, request):
        # ❌ Block unsupported HTTP methods
        if request.method not in self.allowed_methods:
            self.log_block(request, "Invalid HTTP method")
            return HttpResponseForbidden("403 Forbidden")

        # # 🚨 Check payload for SQL/XSS
        try:
            payload = request.GET.urlencode()
            if hasattr(request, "body"):
                payload += request.body.decode(errors="ignore")
        except Exception:
            payload = ""

        if self.is_suspicious(payload, self.sql_patterns):
            self.log_block(request, "SQL Injection")
            return HttpResponseForbidden("403 Forbidden")

        if self.is_suspicious(payload, self.xss_patterns):
            self.log_block(request, "XSS Attack")
            return HttpResponseForbidden("403 Forbidden")

        # ❌ Block bad User-Agent strings
        user_agent = request.META.get("HTTP_USER_AGENT", "").lower()
        if self.is_suspicious(user_agent, self.blocked_agents):
            self.log_block(request, "Malicious User-Agent")
            return HttpResponseForbidden("403 Forbidden")

        # ⏳ Limit anonymous access time
        if not request.user.is_authenticated:
            limit = 10
            last_limit = 0
            
            while (limit != 0):
                limit -= 1
                last_limit += 1
                
                print(f"""
                      
                      limit {limit}
                      last_limit {last_limit}
                      
                      """)
            
            #     try:
            #         first_seen = datetime.datetime.fromisoformat(session["first_seen"])
            #         if (now_time - first_seen).total_seconds() > 60:
            #             self.log_block(request, "Anonymous time limit exceeded")
            #             return HttpResponseForbidden("403 Forbidden")
            #     except Exception:
            #         self.log_block(request, "Invalid session timestamp")
            #         return HttpResponseForbidden("403 Forbidden")
        if request.user.is_anonymous:
            api_key = request.META.get("HTTP_X_APP_TOKEN")
    
            if api_key != VALID_API_KEY:
                self.log_block(request, "Anonymous access without valid Token")
                return HttpResponseForbidden("Invalid API Key")
            else:
                logger.info("✅ Authenticated via API key.")

        return self.get_response(request)
