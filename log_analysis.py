import re
import csv
from collections import Counter, defaultdict

# Configuration
LOG_FILE_PATH = "/workspaces/python/logfiles.log"  # Replace with the path to your log file
THRESHOLD = 10  # Threshold for suspicious activity detection
OUTPUT_CSV = "log_analysis_results.csv"

# Regular expressions to match IPs, endpoints, and failed login attempts
IP_PATTERN = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
ENDPOINT_PATTERN = r"\"(?:GET|POST|PUT|DELETE|HEAD) (.*?) HTTP"
FAILED_LOGIN_PATTERN = r"401|Invalid credentials"  # Adjust based on your log format

# Data containers
ip_counter = Counter()
endpoint_counter = Counter()
failed_login_attempts = defaultdict(int)

# Process the log file
with open(LOG_FILE_PATH, "r") as file:
    for line in file:
        # Extract IP address
        ip_match = re.search(IP_PATTERN, line)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_counter[ip_address] += 1

        # Extract endpoint
        endpoint_match = re.search(ENDPOINT_PATTERN, line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counter[endpoint] += 1

        # Detect failed login attempts
        if re.search(FAILED_LOGIN_PATTERN, line):
            if ip_match:  # Use the IP address from earlier
                failed_login_attempts[ip_address] += 1

# Determine most accessed endpoint
most_accessed_endpoint, max_count = endpoint_counter.most_common(1)[0]

# Identify suspicious activity
suspicious_ips = {
    ip: count for ip, count in failed_login_attempts.items() if count > THRESHOLD
}

# Output results
print("\nRequests per IP:")
print(f"{'IP Address':<20} {'Request Count':<15}")
for ip, count in ip_counter.most_common():
    print(f"{ip:<20} {count:<15}")

print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint} (Accessed {max_count} times)")

print("\nSuspicious Activity Detected:")
print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
for ip, count in suspicious_ips.items():
    print(f"{ip:<20} {count:<15}")

# Save results to CSV
with open(OUTPUT_CSV, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    # Write Requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in ip_counter.items():
        writer.writerow([ip, count])

    writer.writerow([])  # Blank line for separation

    # Write Most Accessed Endpoint
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint, max_count])

    writer.writerow([])

    # Write Suspicious Activity
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])

print(f"\nResults saved to {OUTPUT_CSV}")
