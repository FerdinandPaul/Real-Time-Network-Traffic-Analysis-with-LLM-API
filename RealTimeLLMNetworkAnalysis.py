import csv
from datetime import datetime
import os
from scapy.all import sniff, IP, IPv6, DNS, DNSQR, Ether, UDP, TCP
from openai import OpenAI

# Ensure you have the OpenAI library installed: pip install openai
# Make sure to set your OpenAI API key in your environment variables or directly in the script
client = OpenAI(api_key='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')

log_file_path = '//Users/ferdinandpaul/Documents/get_log/logs5'  # Update this path as needed

domain_category_cache = {}  # Cache for domain categories to minimize API requests
query_count_cache = {}  # Cache for counting domain queries

def initialize_csv():
    """Initialize the CSV log file with headers if it doesn't already exist."""
    headers = ['Timestamp', 'Queried Domain', 'Device IP', 'Source MAC', 'Destination IP', 'Destination MAC', 'Protocol', 'Packet Size', 'DNS Response Code', 'Category', 'Query Count']
    if not os.path.exists(log_file_path):
        with open(log_file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
    else:
        print("CSV file already exists. Continuing with the existing file.")

def categorize_domain(domain_name):
    """Categorize the domain name using OpenAI's API."""
    if domain_name in domain_category_cache:
        return domain_category_cache[domain_name]

    try:
        response = client.completions.create(
            model="gpt-3.5-turbo-instruct",  # Adjust for the latest model as necessary
            prompt=f"What category best describes the website with the domain name: {domain_name}?",
            temperature=0.5,
            max_tokens=10)
        category = response.choices[0].text.strip()
        domain_category_cache[domain_name] = category
        return category
    except Exception as e:
        print(f"An error occurred while categorizing domain: {e}")
        return "Error"

def update_query_count(domain_name):
    """Update the query count for a given domain name."""
    if domain_name in query_count_cache:
        query_count_cache[domain_name] += 1
    else:
        query_count_cache[domain_name] = 1
    return query_count_cache[domain_name]

def process_packet(packet):
    """Process each packet captured, extract DNS query information, and categorize domain."""
    if DNSQR in packet and packet.haslayer(DNS):
        queried_domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        category = categorize_domain(queried_domain)
        query_count = update_query_count(queried_domain)

        packet_details = {
            'device_ip': packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else 'N/A'),
            'source_mac': packet[Ether].src,
            'destination_ip': packet[IP].dst if IP in packet else (packet[IPv6].dst if IPv6 in packet else 'N/A'),
            'destination_mac': packet[Ether].dst,
            'protocol': 'TCP' if TCP in packet else ('UDP' if UDP in packet else 'N/A'),
            'packet_size': len(packet),
            'dns_response_code': packet[DNS].rcode if packet[DNS].qr == 1 and packet[DNS].ancount > 0 else 'N/A',
            'category': category,
            'query_count': query_count
        }

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        log_visit(timestamp, queried_domain, **packet_details)


def log_visit(timestamp, queried_domain, device_ip, source_mac, destination_ip, destination_mac, protocol, packet_size, dns_response_code, category, query_count):
    """Log the details of each DNS query to the CSV file."""
    with open(log_file_path, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([timestamp, queried_domain, device_ip, source_mac, destination_ip, destination_mac, protocol, packet_size, dns_response_code, category, query_count])

def start_sniffing():
    """Start sniffing network traffic for DNS queries."""
    print("Starting DNS query sniffing...")
    sniff(prn=process_packet, filter="udp port 53 or tcp port 53", store=False)

if __name__ == "__main__":
    initialize_csv()
    start_sniffing()
