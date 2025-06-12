import pandas as pd
import re

with open("sample_logs.txt","r") as file:
    raw_logs=file.readlines()

# Parse each line with regex and Extract Data
parsed_logs=[]

log_pattern=re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>GET|POST) (?P<endpoint>[^\s]+) HTTP/1.1" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)

for line in raw_logs:
    match=log_pattern.search(line)
    if match:
        parsed_logs.append(match.groupdict())

# print(parsed_logs)

#Create a Pandas Dataframe
df=pd.DataFrame(parsed_logs)
print(df.head())

#Analyzing the logs
print("Top Ips",df['ip'].value_counts())
print("Suspicious Status Codes: ",df[df['status'].isin(['403','401'])])

known_iocs = {"203.0.113.5", "198.51.100.23"}
ioc_hits=df[df['ip'].isin(known_iocs)]
print("Indiactors of Compromise")
print(ioc_hits)