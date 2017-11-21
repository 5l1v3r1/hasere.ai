from scapy.all import *
from utils import full_duplex

try:
	import scapy_http.http
except ImportError:
	from scapy.layers import http


request_types = {"1":"A","28":"AAAA","15":"MX","33":"SRV","16":"TXT","12":"PTR","255":"*","29":"LOC","2":"NS"}


def is_ip(string):
	import socket
	try:
		socket.inet_aton(string)
		return True
	except:
		return False

class NetworkFeatures:
	def __init__(self,sample_name):
		self.pcap = None
		self.requested_domains = []
		self.sample_name = sample_name
		self.number_of_udp_connections = 0
		self.number_of_distinct_ip_addresses = 0
		self.number_of_distinct_udp_dst_ports = 0
		self.number_of_irc_connections = 0
		self.number_of_http_connections = 0
		self.number_of_smtp_connections = 0
		self.number_of_tcp_connections = 0
		self.number_of_icmp_connections = 0
		self.number_of_hosts = 0
		self.number_of_hosts = 0
		self.number_of_hosts_with_reverse_dns = 0
		self.number_of_dns_requests = 0
		self.dns_request_type_frequency = {"A":0,"AAAA":0,"MX":0,"SRV":0,"TXT":0,"PTR":0,"LOC":0,"*":0,"NS":0}
		self.number_of_domains = 0
		self.domain_level_frequency = {"0":0,"1":0,"2":0,"3":0}
		self.domain_name_length_frequency = {"0":0, "1":0, "2":0, "3":0,"4":0}
	
	def read_pcap(self):
		self.pcap = rdpcap(self.sample_name)
	
	def extract_features(self):
		import time
		start = time.time()
		http_sessions = []
		http_counter = 0
		smtp_sessions = []
		smtp_counter = 0
		irc_sessions = []
		irc_counter = 0

		sessions = self.pcap.sessions(full_duplex).keys()
		for session in sessions:
			if "UDP" in session:
				self.number_of_udp_connections += 1
			elif "TCP" in session:
				self.number_of_tcp_connections += 1
				tcp_packets = self.pcap.sessions(full_duplex)[session]
				for tcp_packet in tcp_packets:
					if "HTTP" in tcp_packet:
						http_counter +=1
					elif "IRC" in tcp_packet:
						irc_counter += 1
					elif "SMTP" in tcp_packet:
						smtp_counter += 1
				
				http_sessions.append(http_counter)
				http_counter = 0
				irc_sessions.append(irc_counter)
				irc_counter = 0
				smtp_sessions.append(smtp_counter)
				smtp_counter = 0
						
			elif "ICMP" in session:
				self.number_of_icmp_connections += 1
		
		self.number_of_http_connections = len(filter(lambda a:a !=0, http_sessions))
		self.number_of_smtp_connections = len(filter(lambda a:a !=0, smtp_sessions))
		self.number_of_irc_connections = len(filter(lambda a:a !=0, irc_sessions))
		
		ip_list = set()
		udp_dst_ports = set()
		
		for packet in self.pcap:
			if packet.haslayer("IP"):
				ip_list.add(packet.getlayer("IP").dst)
			if packet.haslayer("UDP"):
				udp_dst_ports.add(packet.getlayer("UDP").dport)
			if packet.haslayer("DNS"):
				dns_layer = packet.getlayer("DNS")
				if dns_layer.qr == 0L:
					self.number_of_dns_requests += 1
					self.dns_request_type_frequency[request_types[str(dns_layer.qd.qtype)]] += 1
					self.requested_domains.append(str(dns_layer.qd.qname)[0:len(str(dns_layer.qd.qname))-1])
				elif dns_layer.qr == 1L:
					if hasattr(dns_layer.an, "rdata"):
						if is_ip(dns_layer.an.rdata):
							self.number_of_hosts += 1

		self.number_of_domains = len(self.requested_domains)
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
			
			tokens = domain.split(".")
			if len(tokens) <= 2:
				self.domain_level_frequency["0"] += 1
			elif len(tokens) == 3:
				self.domain_level_frequency["1"] += 1
			elif len(tokens) == 4:
				self.domain_level_frequency["2"] += 1
			elif len(tokens) > 4:
				self.domain_level_frequency["3"] += 1
		
		self.number_of_distinct_ip_addresses = len(ip_list)
		self.number_of_distinct_udp_dst_ports = len(udp_dst_ports)
		
		print "Elapsed time: " + str(time.time() - start)
		print ""
	
	def info(self):
		print "Sample name: " + self.sample_name
		
		print ""
		
		print "number of udp connections: " + str(self.number_of_udp_connections)
		print "number of tcp connections: " + str(self.number_of_tcp_connections)
		print "number of icmp connections: " + str(self.number_of_icmp_connections)
		
		print ""
		
		print "number of http connections: " + str(self.number_of_http_connections)
		print "number of smtp connections: " + str(self.number_of_smtp_connections)
		print "number of irc connections: " + str(self.number_of_irc_connections)
		
		print ""
		
		print "number of distinct ip addresses: " + str(self.number_of_distinct_ip_addresses)
		print "number of distinct udp dst ports: " + str(self.number_of_distinct_udp_dst_ports)
		
		print ""
		
		print "number of dns requests: " + str(self.number_of_dns_requests)
		print "number of hosts: " + str(self.number_of_hosts)
		print "number of domains: " + str(self.number_of_domains)
		print "number of distinct domains: " + str(len(set(self.requested_domains)))
		print ""
		print "domain level frequency:"
		print self.domain_level_frequency
		print ""
		print "domain name length frequency:"
		print self.domain_name_length_frequency
		print ""
		print "dns request type frequency:"
		print self.dns_request_type_frequency
		
		print ""
		
		
if __name__ == "__main__":
	networkFeatures = NetworkFeatures("samples/dns.cap")
	networkFeatures.read_pcap()
	networkFeatures.extract_features()
	networkFeatures.info()