import os
import sys

SPLUNK_HOST = os.environ.get("SPLUNK_HOST")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN")

if not SPLUNK_HOST or SPLUNK_TOKEN:
    print("URL Splunk o Token di autenticazione non trovati")
    sys.exit(1)

