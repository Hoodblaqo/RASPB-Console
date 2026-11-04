#!/usr/bin/env python3
"""Tiny a-Shell-friendly client for RASPB Console accounts and private inbox."""
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from getpass import getpass

def main():
    base = input("RASPB server URL (https://...): ").strip().rstrip("/")
    if not base.startswith("https://"):
        print("Use the HTTPS URL from your deployment.")
        return
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def request(path, data=None):
        body = urllib.parse.urlencode(data).encode() if data else None
        req = urllib.request.Request(base + path, data=body)
        try:
            with opener.open(req, timeout=15) as response:
                return response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return "HTTP " + str(exc.code) + ": " + exc.read().decode("utf-8", "replace")
        except Exception as exc:
            return "Connection error: " + str(exc)
    print("Open the web interface for registration and owner controls.")
    print("This lightweight client is a connection check, not a replacement for the web admin panel.")
    username = input("Username: ").strip()
    password = getpass("Password: ")
    result = request("/login", {"username": username, "password": password})
    print(result[:1200])
    print("For full account controls and private notices, open the server URL in Safari.")
if __name__ == "__main__":
    main()
