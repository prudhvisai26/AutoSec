import re

# Read and parse the log
with open("sample_logs.txt","r") as file:
    logs=file.readlines()  #reads the entire file and returns a list where each line is one item.

for line in logs:
    line.strip()   #removes any whitespace or newline characters (\n).

# Extracing ips using regex    
"""
This defines a regex pattern to match IPv4 addresses like 192.168.1.101.
\d{1,3} means "1 to 3 digits"
(\d{1,3}\.){3} means "1 to 3 digits followed by a dot, repeated 3 times"
\d{1,3} at the end captures the last segment
"""

ip_pattern=re.compile(r"(\d{1,3}\.){3}\d{1,3}")

suspicious_ips=[]
for line in logs:
    match=ip_pattern.search(line) #looks for the first match of the IP pattern.
    if match:
        ip=match.group()
        suspicious_ips.append(ip)  

# print(logs)
print("All IPs found: ",suspicious_ips)

# Matching against known IOCs
known_iocs={"203.0.113.5","198.51.100.23"}

for ip in suspicious_ips:
    if ip in known_iocs:
        print(f"Alert: IOC detected! Malicious IP: {ip}")

#Writing Malicious Ips to a File
with open("ioc_alerts.txt","w") as alert_file:
    for ip in suspicious_ips:
        if ip in known_iocs:
            alert_file.write(f"Malicious Ip Detected: {ip}\n")