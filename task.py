import csv
from collections import Counter
from datetime import datetime
import re

# Function to count requests per IP
def count_requests_per_ip(file_path):
    ip_counts = Counter()
    try:
        with open(file_path, 'r') as file:
            ip_counts.update(line.split()[0] for line in file.readlines())
    except Exception as e:
        print(f"Error in counting requests per IP: {e}")
    return ip_counts

# Function to find the most accessed endpoint
def find_most_accessed_endpoint(file_path):
    endpoint_counts = Counter()
    try:
        with open(file_path, 'r') as file:
            endpoint_counts.update(line.split()[6] for line in file.readlines())
    except Exception as e:
        print(f"Error in counting endpoints: {e}")
    return endpoint_counts

# Function to detect brute force login attempts
def detect_brute_force(file_path, threshold=10):
    failed_logins = Counter()
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if '401' in line or 'Invalid credentials' in line:
                    ip_address = line.split()[0]
                    failed_logins[ip_address] += 1
    except Exception as e:
        print(f"Error in detecting brute force: {e}")
    
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    if not flagged_ips:
        print("No potential brute force attempts detected.")
    
    return flagged_ips, len(flagged_ips), max(failed_logins.values(), default=0)

# Function to analyze traffic by time (hourly)
def analyze_traffic_by_time(file_path):
    log_pattern = r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]'
    traffic_by_time = Counter()
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.search(log_pattern, line)
                if match:
                    timestamp_str = match.group(1)
                    timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
                    time_period = timestamp.strftime("%Y-%m-%d %H:00")  # Group by hour
                    traffic_by_time[time_period] += 1
    except Exception as e:
        print(f"Error in analyzing traffic by time: {e}")
    
    return traffic_by_time

# Function to save results to CSV
def save_results_to_csv(request_counts, endpoint_counts, flagged_ips, brute_force_summary, output_file, most_accessed_endpoint, traffic_by_time):
    try:
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write Requests per IP
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in sorted(request_counts.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([ip, count])
            
            writer.writerow([])  # Empty line for separation
            
            # Write Most Accessed Endpoint
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            for endpoint, count in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([endpoint, count])
            
            if most_accessed_endpoint:
                writer.writerow([])  # Empty line for separation
                writer.writerow([f"Most accessed endpoint: {most_accessed_endpoint[0]} with {most_accessed_endpoint[1]} requests."])
            
            writer.writerow([])  # Empty line for separation
            
            # Write Suspicious Activity
            writer.writerow(["Suspicious Activity"])
            if not flagged_ips:
                writer.writerow(["No potential brute force attempts detected."])
            else:
                writer.writerow(["IP Address", "Failed Login Count"])
                for ip, count in flagged_ips.items():
                    writer.writerow([ip, count])
                writer.writerow([])  # Empty line
                writer.writerow([f"Total flagged IPs: {brute_force_summary[1]}"])
            writer.writerow([])  # Empty line for separation
            # Write Traffic Pattern Over Time
            writer.writerow(["Traffic Pattern Over Time"])
            writer.writerow(["Time Period", "Request Count"])
            if traffic_by_time:
                for time_period, count in sorted(traffic_by_time.items()):
                    writer.writerow([time_period, count])
            else:
                writer.writerow(["No traffic data found."])  # In case no data is found
            
    except Exception as e:
        print(f"Error in saving results to CSV: {e}")

# Main function to process log file and display results
def main(log_file_path, output_csv_file):
    
    # Count requests per IP
    request_counts = count_requests_per_ip(log_file_path)
    print(f"{'IP Address':<20}{'Request Count':<15}")
    print("-" * 35)
    for ip, count in sorted(request_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count:<15}")
    
    print("\n")
    
    # Find most accessed endpoint
    endpoint_counts = find_most_accessed_endpoint(log_file_path)
    print(f"{'Endpoint':<30}{'Access Count':<15}")
    print("-" * 45)
    for endpoint, count in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{endpoint:<30}{count:<15}")
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=(None, 0))
    if most_accessed_endpoint[0]:
        print(f"\nMost accessed endpoint: {most_accessed_endpoint[0]} with {most_accessed_endpoint[1]} requests.")
    else:
        print("\nNo endpoints found in the log file.")
    
    print("\n")
    
    # Detect brute force login attempts
    flagged_ips, total_flagged_ips, max_failed_attempts = detect_brute_force(log_file_path, threshold=5)
    print(f"{'IP Address':<20}{'Failed Login Count':<15}")
    print("-" * 35)
    for ip, count in flagged_ips.items():
        print(f"{ip:<20}{count:<15}")
    print(f"\nTotal flagged IPs: {total_flagged_ips}")
    print(f"Maximum failed login attempts: {max_failed_attempts}")
    
    print("\nTraffic Pattern Over Time:")
    traffic_by_time = analyze_traffic_by_time(log_file_path)
    print(f"{'Time Period':<20}{'Request Count':<15}")
    print("-" * 35)
    if traffic_by_time:
        for time_period, count in sorted(traffic_by_time.items()):
            print(f"{time_period:<20}{count:<15}")
    else:
        print("No traffic data found.")
    
    print("\nSaving results to CSV...")
    # print(traffic_by_time)
    # Save all results to CSV
    save_results_to_csv(request_counts, endpoint_counts, flagged_ips, (total_flagged_ips, max_failed_attempts), output_csv_file, most_accessed_endpoint, traffic_by_time)
    print(f"Results saved to {output_csv_file}")

# Run the script
if __name__ == "__main__":
    log_file_path = "sample.log"  # Replace with your actual log file path
    output_csv_file = "log_analysis_results.csv"
    
    main(log_file_path, output_csv_file)
