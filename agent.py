//this is the tool to find cves across networks
//private to cygnia-cortex
  
import re
import requests

# Simple XSS detection regex patterns
xss_patterns = [
    r"<script.*?>.*?</script>",
    r"on\w+\s*=\s*['\"].*?['\"]",              # inline event handlers like onclick="..."
    r"javascript:\s*[^\"']+",                  # javascript: URI
    r"<.*?src\s*=\s*['\"]javascript:.*?['\"]", # src="javascript:..."
    r"<iframe.*?>.*?</iframe>",
    r"<.*?onerror\s*=.*?>",
    r"<.*?alert\s*\(.*?\).*?>",
]

def check_xss_with_regex(url):
    try:
        print(f"[*] Fetching: {url}")
        response = requests.get(url, timeout=5)
        content = response.text

        found = False
        for pattern in xss_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                print(f"[!!] Potential XSS pattern found:\nPattern: {pattern}\nMatches: {matches}\n")
                found = True

        if not found:
            print("[+] No suspicious XSS patterns found.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    target_url = input("Enter the target URL to scan: ")
    check_xss_with_regex(target_url)
