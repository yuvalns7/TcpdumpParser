# **TCPDump Parser API**

## 📌 Overview

A **TCPDump Parser API** that processes network traffic logs, detects anomalies, and generates structured reports. It allows users to upload TCPDump logs via an HTTP API, analyze packet data, and receive detailed insights.

## ✨ Features

- **TCPDump Parsing**: Extracts details from TCP, UDP, and ICMP packets.
- **Anomaly Detection**: Identifies malformed packets, missing fields, incorrect formats, and unexpected values.
- **Protocol & Traffic Analysis**: Tracks network traffic, protocol usage, and application-layer data (HTTP, DNS, TLS).
- **Security Insights**: Detects incomplete TCP handshakes, SYN flood attacks, and suspicious traffic patterns.
- **Structured Reports**: Generates downloadable logs with packet summaries, protocol statistics, and connection insights.
- **REST API**: Upload tcpdump logs via a simple HTTP endpoint and retrieve structured reports.

## 🚀 Getting Started

### 1️⃣ Install Dependencies
```sh
npm install
```

### 2️⃣ Start the Server
```sh
npm start
```
Server runs at `http://localhost:3000`

## 🔥 API Usage

### **Upload a TCPDump File**
#### Endpoint:
```
POST /api/parseTcpdumpFile
```
#### Request:
- **Body:** `multipart/form-data`
- **Field Name:** `file`
- **File Type:** `.txt`

#### Example:
```sh
curl -X POST -F "file=@example1.txt" http://localhost:3000/api/parseTcpdumpFile --output report.log
```

#### Response:
- Returns a downloadable analysis report.

## 📊 Report Breakdown

The system generates structured reports with insights into **packet distribution, protocol usage, IP statistics, and potential security threats**.

### **Key Report Sections:**
1️⃣ **Packet Summary** – Total processed packets, valid vs. malformed.  
2️⃣ **Protocol Breakdown** – Distribution of TCP, UDP, and ICMP traffic.  
3️⃣ **Application Analysis** – Detects HTTP, DNS, and TLS packets.  
4️⃣ **Port Usage** – Identifies frequently used and non-standard ports.  
5️⃣ **IP Statistics** – Tracks unique IPs and their activity.  
6️⃣ **TCP Handshake Analysis** – Detects incomplete connections.  
7️⃣ **Packet Size Insights** – Minimum, maximum, and average packet sizes.  
8️⃣ **SYN Flood Detection** – Flags potential SYN flood attacks.  

---

## ⚠ Anomaly Detection

The API detects and flags anomalies in network traffic, including:

- **Structural Issues**: Missing fields, incorrect formatting, misplaced values.
- **TCP Anomalies**: Incomplete handshakes, incorrect flag sequences.
- **UDP & ICMP Issues**: Missing ports, invalid lengths.
- **HTTP & DNS Anomalies**: Traffic on unexpected ports, malformed packets.
