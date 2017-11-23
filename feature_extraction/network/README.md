
# Network Features

İncelenen dosyaların network etkinliklerine ait özellikler

# Features

| Status | Id | Size | Feature |
| ------ | ------ | ------ | ------ |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-Yellow.svg)](https://shields.io/)
 | 1 | 1 | Number of ICMP Connections |
| [ ] | 2 | 1 | Number of TCP Connections |
| [ ] | 3 | 1 | Number of UDP Connections |
| [ ] | 4 | 1 | Number of HTTP Connections |
| [ ] | 5 | 1 | Number of SMTP Connections |
| [ ] | 6 | 1 | Number of IRC Connections |
| [ ] | 7 | 1 | Number of Distinct IP Address |
| [ ] | 8 | 1 | Number of Distinct UDP Destination Ports |
| [ ] | 9 | 1 | Number of Hosts |
| [ ] | 10 | 1 | Number of Hosts with Reverse DNS |
| [ ] | 11 | 1 | Number of DNS Requests |
| [ ] | 12 | 1 | Number of Domains |
| [ ] | 13 | 9 | DNS Request Type Frequency |
| [ ] | 14 | 4 | Domain Level Frequency |
| [ ] | 15 | 5 | Domain Name Length Frequency |

> Bağlantı sayıları hesaplanırken karşılıklı tekil bağlantıları elde etmek için **full_duplex** adlı fonksiyon kullanılmıştır.
```python
def full_duplex(p):
	sess = "Other"
	if 'Ether' in p:
		if 'IP' in p:
			if 'TCP' in p:
				sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport], key=str))
			elif 'UDP' in p:
				sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport], key=str))
			elif 'ICMP' in p:
				sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id], key=str))
			else:
				sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto], key=str))
		elif 'ARP' in p:
			sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst], key=str))
		else:
			sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
	return sess
```

#### Number of ICMP Connections
Kurulan tüm ICMP bağlantılarının sayısıdır. ICMP'de varsayılan olarak connection kurulmadığından karşılıklı IP adresleri ve ICMP Request ve Response paketleri baz alınarak hesaplanmıştır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
for session in sessions:
    if "ICMP" in session:
        self.number_of_icmp_connections += 1
```

#### Number of TCP Connections
Kurulan tüm TCP bağlantılarının sayısıdır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
for session in sessions:
    if "TCP" in session:
        self.number_of_icmp_connections += 1
```

#### Number of UDP Connections
Kurulan tüm UDP bağlantılarının sayısıdır. UDP'de varsayılan olarak connection kurulmadığından karşılıklı IP adresleri baz alınarak hesaplanmıştır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
for session in sessions:
    if "UDP" in session:
        self.number_of_icmp_connections += 1
```

#### Number of HTTP Connections
Kurulan tüm HTTP bağlantılarının sayısıdır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
http_session_counter = 0
http_sessions = []
for session in sessions:
    if "TCP" in session:
        tcp_packets = self.pcap.sessions(full_duplex)[session]
        for tcp_packet in tcp_packets:
            if "HTTP" in tcp_packet:
                http_session_counter +=1
    http_sessions.append(http_counter)
    http_counter = 0
self.number_of_http_connections = len(filter(lambda a:a !=0, http_sessions))
```

#### Number of SMTP Connections
Kurulan tüm SMTP bağlantılarının sayısıdır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
smtp_session_counter = 0
smtp_sessions = []
for session in sessions:
    if "TCP" in session:
        tcp_packets = self.pcap.sessions(full_duplex)[session]
        for tcp_packet in tcp_packets:
            if "SMTP" in tcp_packet:
                http_session_counter +=1
    http_sessions.append(http_counter)
    http_counter = 0
self.number_of_http_connections = len(filter(lambda a:a !=0, smtp_sessions))
```

