
# Network Features [![Generic badge](https://img.shields.io/badge/1-Failed-red.svg)](https://shields.io/) [![Generic badge](https://img.shields.io/badge/14-Waiting-yellow.svg)](https://shields.io/) [![Generic badge](https://img.shields.io/badge/2-New-blue.svg)](https://shields.io/)

İncelenen dosyalara ait Network etkinliklerine ait özellikler ve bu özelliklerin Cuckoo raporundan çıkarılması için oluşturulmuş fonksiyonlar listelenmiştir.

# Features

| Status | Id | Size | Feature |
| ------ | ------ | ------ | ------ |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 1 | 1 | Number of ICMP Connections |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 2 | 1 | Number of TCP Connections |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 3 | 1 | Number of UDP Connections |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 4 | 1 | Number of HTTP Connections |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 5 | 1 | Number of SMTP Connections |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 6 | 1 | Number of IRC Connections |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 7 | 1 | Number of Distinct IP Address |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 8 | 1 | Number of Distinct UDP Destination Ports |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 9 | 1 | Number of Hosts |
| [![Generic badge](https://img.shields.io/badge/Test-Failed-red.svg)](https://shields.io/) | 10 | 1 | Number of Hosts with Reverse DNS |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 11 | 1 | Number of DNS Requests |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 12 | 1 | Number of Domains |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 13 | 9 | DNS Request Type Frequency |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 14 | 4 | Domain Level Frequency |
| [![Generic badge](https://img.shields.io/badge/Test-Waiting-yellow.svg)](https://shields.io/) | 15 | 5 | Domain Name Length Frequency |
| [![Generic badge](https://img.shields.io/badge/New-Feature-blue.svg)](https://shields.io/) | 16 | 1 | Average Domain Name Entropy |
| [![Generic badge](https://img.shields.io/badge/New-Feature-blue.svg)](https://shields.io/) | 17 | 5 | Domain Name Entropy Frequency |
| [![Generic badge](https://img.shields.io/badge/New-Feature-blue.svg)](https://shields.io/) | 17 | 1 | Number of SMB Connection |
| [![Generic badge](https://img.shields.io/badge/New-Feature-blue.svg)](https://shields.io/) | 17 | 1 | MITM Attempt |

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

### Number of ICMP Connections
Kurulan tüm ICMP bağlantılarının sayısıdır. ICMP'de varsayılan olarak connection kurulmadığından karşılıklı IP adresleri ve ICMP Request ve Response paketleri baz alınarak hesaplanmıştır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
for session in sessions:
    if "ICMP" in session:
        self.number_of_icmp_connections += 1
```

### Number of TCP Connections
Kurulan tüm TCP bağlantılarının sayısıdır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
for session in sessions:
    if "TCP" in session:
        self.number_of_icmp_connections += 1
```

### Number of UDP Connections
Kurulan tüm UDP bağlantılarının sayısıdır. UDP'de varsayılan olarak connection kurulmadığından karşılıklı IP adresleri baz alınarak hesaplanmıştır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
for session in sessions:
    if "UDP" in session:
        self.number_of_icmp_connections += 1
```

### Number of HTTP Connections
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

### Number of SMTP Connections
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
                smtp_session_counter +=1
    smtp_sessions.append(smtp_counter)
    smtp_counter = 0
self.number_of_smtp_connections = len(filter(lambda a:a !=0, smtp_sessions))
```

### Number of IRC Connections
Kurulan tüm IRC bağlantılarının sayısıdır.

```python
sessions = self.pcap.sessions(full_duplex).keys()
irc_session_counter = 0
irc_sessions = []
for session in sessions:
    if "TCP" in session:
        tcp_packets = self.pcap.sessions(full_duplex)[session]
        for tcp_packet in tcp_packets:
            if "IRC" in tcp_packet:
                irc_session_counter +=1
    irc_sessions.append(irc_counter)
    irc_counter = 0
self.number_of_irc_connections = len(filter(lambda a:a !=0, irc_sessions))
```

### Number of Distinct IP Address
Haberleşilen tekil IP sayısıdır.

```python
distinct_ips = set()
for packet in self.pcap:
    if packet.haslayer("IP"):
        distinct_ips.add(packet.getlayer("IP").dst)
self.number_of_distinct_ip_addresses = len(ip_list)
```

### Number of Distinct UDP Destination Ports
Haberleşilen tekil UDP hedef port sayısıdır.

```python
distinct_udp_dst_ports = set()
for packet in self.pcap:
    if packet.haslayer("UDP"):
       distinct_udp_dst_ports.add(packet.getlayer("UDP").dport)
self.number_of_distinct_udp_dst_ports = len(distinct_udp_dst_ports)
```

### Number of Hosts
DNS sorgusu yapılarak öğrenilen toplam IP adresi sayısıdır.

```python
for packet in self.pcap:
    if packet.haslayer("DNS"):
       dns_layer = packet.getlayer("DNS")
        if dns_layer.qr == 1L:
            if hasattr(dns_layer.an, "rdata"):
                if is_ip(dns_layer.an.rdata):
                    self.number_of_hosts += 1
```

### Number of Hosts with Reverse DNS
Reverse DNS sorgusu yapılan toplam IP sayısıdır.

### Number of DNS Requests
Toplam DNS sorgusu sayısıdır.

```python
for packet in self.pcap:
    if packet.haslayer("DNS"):
       dns_layer = packet.getlayer("DNS")
        if dns_layer.qr == 0L:
            self.number_of_dns_requests += 1
```

### Number of Domains
DNS sorgusu yapılan toplam domain sayısıdır.

```python
requested_domains = []
for packet in self.pcap:
    if packet.haslayer("DNS"):
       dns_layer = packet.getlayer("DNS")
        if dns_layer.qr == 0L:
            self.requested_domains.append(str(dns_layer.qd.qname)[0:len(str(dns_layer.qd.qname))-1])
self.number_of_domains = len(self.requested_domains)
```

### DNS Request Type Frequency
DNS sorgularının türüne göre hesaplanmış frekans değeridir. Bir request türü ile yapılan toplam istek sayısı vektörün ilgili hücresini oluşturmaktadır.

```python
for packet in self.pcap:
    if packet.haslayer("DNS"):
       dns_layer = packet.getlayer("DNS")
        if dns_layer.qr == 0L:
            self.dns_request_type_frequency[request_types[str(dns_layer.qd.qtype)]] += 1
```

#### Dns Sorgu Türleri
| A | AAAA | CNAME | SIG |
| ------ | ------ | ------ | ------ |
| **SOA** | **NS** |**MX** | **SRV** |
| **TXT** | **PTR** | **LOC** | **ANY(\*)** |

### Domain Level Frequency
Domainlerin belirlenen 4 seviyeye göre hesaplanmış frekans değeridir. O seviyedeki toplam domain sayısı vektörün ilgili hücresini oluşturmaktadır.

```python
for domain in self.requested_domains:
    tokens = domain.split(".")
    if len(tokens) <= 2:
		self.domain_level_frequency["0"] += 1
	elif len(tokens) == 3:
		self.domain_level_frequency["1"] += 1
	elif len(tokens) == 4:
		self.domain_level_frequency["2"] += 1
	elif len(tokens) > 4:
		self.domain_level_frequency["3"] += 1
```

#### Domain Seviyeleri
| Level Type | Example |
| ------ | ------ |
|top-level|domain.com|
|second-level|sub1.domain.com|
|third-level|sub2.sub1.domain.com|
|fourth-level|subn...sub1.domain.com|

### Domain Name Length Frequency
Domain isimlerinin uzunluklarına göre oluşturulmuş 5 grup için hesaplanmış frekans değeridir. O grup uzunluk aralığındaki toplam domain sayısı vektörün ilgili hücresini oluşturmaktadır.
```python
for domain in self.requested_domains:
	domain_length = len(domain)
	if domain_length <= 10:
		self.domain_name_length_frequency["0"] += 1
	elif domain_length <= 16:
		self.domain_name_length_frequency["1"] += 1
	elif domain_length <= 20:
		self.domain_name_length_frequency["2"] += 1
	elif domain_length <= 32:
		self.domain_name_length_frequency["3"] += 1
	elif domain_length > 32:
		self.domain_name_length_frequency["4"] += 1
```

#### Oluşturulan Gruplar
| Tür | Uzunluk |
| ------| ------ |
|0| 0-10 |
|1| 11-16 |
|2| 17- 20 |
|3| 20-32 |
|4| 32-* |

