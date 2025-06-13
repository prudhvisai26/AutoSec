import pandas as pd
import re
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

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

#Create a Pandas Dataframe
df=pd.DataFrame(parsed_logs)

# Feature Engineering

# Convert categorical data to numbers
# Map method to numeric
df['method_code']=df['method'].map({'GET':0,'POST':1})

# Map suspicious endpoints
suspicious_endpoints=['/admin','/bin/bash','/secret']
df['suspicious']=df['endpoint'].isin(suspicious_endpoints).astype(int)

# Convert status code to int
df['status']=df['status'].astype(int)

print(df[['method_code','status','suspicious']])

# Train Isolation Forest

X=df[['method_code','status','suspicious']]

model=IsolationForest(contamination=0.25,random_state=42)
model.fit(X)

#Predit anomalies
df['anomaly']=model.predict(X)
print(df[['ip','anomaly']])

# Visualize the Result
colors = df['anomaly'].map({1: 'green', -1: 'red'})
plt.figure(figsize=(10, 6))
bars = plt.barh(df['ip'], df['size'], color=colors)
plt.xlabel("Request Size")
plt.title("Anomaly Detection by Request Size and IP")
plt.grid(True, linestyle='--', alpha=0.6)
plt.tight_layout()
plt.show()