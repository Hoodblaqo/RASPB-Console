#!/usr/bin/env python3
"""a-Shell-friendly login helper for the hosted RASPB Console."""
import http.cookiejar
import re
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
    try:
        with opener.open(base + "/login", timeout=15) as response:
            login_page = response.read().decode("utf-8", "replace")
        match = re.search(r'name="csrf_token" value="([^"]+)"', login_page)
        if not match:
            print("Could not load the login form. Check the server URL.")
            return
        username = input("Username: ").strip()
        password = getpass("Password: ")
        data = urllib.parse.urlencode({
            "username": username,
            "password": password,
            "csrf_token": match.group(1),
        }).encode()
        req = urllib.request.Request(base + "/login", data=data)
        with opener.open(req, timeout=15) as response:
            result = response.read().decode("utf-8", "replace")
        if "Account locked" in result:
            print("This account is locked. Open the server URL in Safari to read the private notice.")
        elif "Owner panel" in result:
            print("Signed in as owner. Use Safari for the full admin panel.")
        elif "Your account" in result:
            print("Signed in. Use Safari to view your private inbox.")
        else:
            print("Login response received. Open the server URL in Safari for the full interface.")
    except urllib.error.HTTPError as exc:
        print("HTTP", exc.code, exc.read().decode("utf-8", "replace")[:500])
    except Exception as exc:
        print("Connection error:", exc)

if __name__ == "__main__":
    main()
