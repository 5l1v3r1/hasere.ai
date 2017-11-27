from scapy.all import *
from utils import full_duplex
import json

try:
	import scapy_http.http
except ImportError:
	from scapy.layers import http
	
from scapy_ssl_tls.ssl_tls import *


request_types = {"1":"A","28":"AAAA","15":"MX","33":"SRV","16":"TXT","12":"PTR","255":"*","29":"LOC","2":"NS"}


def is_ip(string):
	import socket
	try:
		socket.inet_aton(string)
		return True
	except:
		return False

class NetworkFeatures:
	def __init__(self,sample_name,report_path):
		self.pcap = None
		self.report = None
		self.sessions = None
		self.requested_domains = []
		self.sample_name = sample_name
		self.report_path = report_path
		self.number_of_udp_connections = 0
		self.number_of_distinct_ip_addresses = 0
		self.number_of_distinct_udp_dst_ports = 0
		self.number_of_distinct_dns_dst_ports = 0
		self.number_of_irc_connections = 0
		self.number_of_http_connections = 0
		self.number_of_smtp_connections = 0
		self.number_of_smb_connections = 0
		self.number_of_ssl_connections = 0
		self.number_of_tcp_connections = 0
		self.number_of_icmp_connections = 0
		self.number_of_hosts = 0
		self.number_of_dns_requests = 0
		self.dns_request_type_frequency = {"A":0,"AAAA":0,"MX":0,"SRV":0,"TXT":0,"PTR":0,"LOC":0,"*":0,"NS":0}
		self.number_of_domains = 0
		self.domain_level_frequency = {"0":0,"1":0,"2":0,"3":0}
		self.domain_name_length_frequency = {"0":0, "1":0, "2":0, "3":0,"4":0}
		self.is_mitm_performed = None
	
	def initialize(self):
		self.read_pcap()
		self.sessions = self.pcap.sessions(full_duplex)
		self.read_report()
	
	def read_report(self):
		self.report = json.load(open(self.report_path))
		
	def read_pcap(self):
		self.pcap = rdpcap(self.sample_name)
		
	def set_connection_features(self):
		http_sessions = []
		http_counter = 0
		smtp_sessions = []
		smtp_counter = 0
		irc_sessions = []
		irc_counter = 0
		smb_sessions = []
		smb_counter = 0
		ssl_sessions = []
		ssl_counter = 0
		
		for session in self.sessions.keys() :
			if "UDP" in session :
				self.number_of_udp_connections += 1
			elif "TCP" in session :
				self.number_of_tcp_connections += 1
				tcp_packets = self.sessions[session]
				
				
				for tcp_packet in tcp_packets :
					
					if tcp_packet.haslayer("HTTP"):
						http_counter += 1
					elif tcp_packet.haslayer("IRC") :
						irc_counter += 1
					elif tcp_packet.haslayer("SMTP") :
						smtp_counter += 1
					elif tcp_packet.haslayer("SMB"):
						smb_counter += 1
					elif tcp_packet.haslayer("SSL"):
						ssl_counter += 1
				
				http_sessions.append(http_counter)
				http_counter = 0
				irc_sessions.append(irc_counter)
				irc_counter = 0
				smtp_sessions.append(smtp_counter)
				smtp_counter = 0
				smb_sessions.append(smb_counter)
				smb_counter = 0
				ssl_sessions.append(ssl_counter)
				ssl_counter = 0
			
			elif "ICMP" in session :
				self.number_of_icmp_connections += 1
		
		self.number_of_http_connections = len(filter(lambda a : a != 0, http_sessions))
		self.number_of_smtp_connections = len(filter(lambda a : a != 0, smtp_sessions))
		self.number_of_irc_connections = len(filter(lambda a : a != 0, irc_sessions))
		self.number_of_smb_connections = len(filter(lambda a : a != 0, smb_sessions))
		self.number_of_ssl_connections = len(filter(lambda a : a != 0, ssl_sessions))
	
	def set_dns_features(self):
		ip_list = set()
		udp_dst_ports = set()
		dns_dst_ports = set()
		
		for packet in self.pcap :
			if packet.haslayer("IP") :
				ip_list.add(packet.getlayer("IP").dst)
			if packet.haslayer("UDP") :
				udp_dst_ports.add(packet.getlayer("UDP").dport)
			if packet.haslayer("DNS") :
				dns_layer = packet.getlayer("DNS")
				try:
					dns_dst_ports.add(packet.getlayer("UDP").dport)
				except:
					try:
						dns_dst_ports.add(packet.getlayer("TCP").dport)
					except:
						pass
					pass
				if dns_layer.qr == 0L :
					self.number_of_dns_requests += 1
					self.dns_request_type_frequency[request_types[str(dns_layer.qd.qtype)]] += 1
					self.requested_domains.append(str(dns_layer.qd.qname)[0 :len(str(dns_layer.qd.qname)) - 1])
				elif dns_layer.qr == 1L :
					if hasattr(dns_layer.an, "rdata") :
						if is_ip(dns_layer.an.rdata) :
							self.number_of_hosts += 1
		
		self.number_of_domains = len(self.requested_domains)
		self.number_of_distinct_ip_addresses = len(ip_list)
		self.number_of_distinct_udp_dst_ports = len(udp_dst_ports)
		self.number_of_distinct_dns_dst_ports = len(dns_dst_ports)
	
	def set_domain_features(self):
		for domain in self.requested_domains :
			domain_length = len(domain)
			if domain_length <= 10 :
				self.domain_name_length_frequency["0"] += 1
			elif domain_length <= 16 :
				self.domain_name_length_frequency["1"] += 1
			elif domain_length <= 20 :
				self.domain_name_length_frequency["2"] += 1
			elif domain_length <= 32 :
				self.domain_name_length_frequency["3"] += 1
			elif domain_length > 32 :
				self.domain_name_length_frequency["4"] += 1
			
			tokens = domain.split(".")
			if len(tokens) <= 2 :
				self.domain_level_frequency["0"] += 1
			elif len(tokens) == 3 :
				self.domain_level_frequency["1"] += 1
			elif len(tokens) == 4 :
				self.domain_level_frequency["2"] += 1
			elif len(tokens) > 4 :
				self.domain_level_frequency["3"] += 1
	
	def extract_features(self):
		self.set_connection_features()
		self.set_dns_features()
		self.set_domain_features()
		self.set_mitm_performed()
			
	def set_mitm_performed(self):
		try:
			mitm_info = self.report["network"]["mitm"]
			if len(mitm_info) > 0:
				self.is_mitm_performed = 1
			else:
				self.is_mitm_performed = 0
		except:
			self.is_mitm_performed = 0
	
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
		print "number of smb connections: " + str(self.number_of_smb_connections)
		print "number of ssl connections: " + str(self.number_of_ssl_connections)
		
		print ""
		
		print "number of distinct ip addresses: " + str(self.number_of_distinct_ip_addresses)
		print "number of distinct udp dst ports: " + str(self.number_of_distinct_udp_dst_ports)
		print "number of distinct dns dst ports: " + str(self.number_of_distinct_dns_dst_ports)
		
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
		print "mitm performed: " + str(self.is_mitm_performed)
		
		print ""
		
if __name__ == "__main__":
	networkFeatures = NetworkFeatures("/home/frkn/Desktop/malwy/code/samples/dump4.pcap","/home/frkn/Desktop/malwy/reports/Reports/reports4/report.json")
	networkFeatures.initialize()
	networkFeatures.extract_features()
	networkFeatures.info()