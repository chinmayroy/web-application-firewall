# web-application-firewall

Django middleware to protect your app from SQL Injection, XSS, protocol anomalies, and bad bots.

## Features
- SQL Injection protection
- XSS detection
- Protocol anomaly detection
- Known vulnerability path blocking
- Bad bot and scanner filtering

## Installation
```
pip install web-application-firewall
```
## Usage
Add to your Django settings.py:

```
MIDDLEWARE = [
    # ... other middleware ...
    'waf.middleware.CustomWAFMiddleware',
]
```