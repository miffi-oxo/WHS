#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>


/* Ethernet header */
struct ethheader {
	u_char  ether_dhost[6]; /* destination host address */
	u_char  ether_shost[6]; /* source host address */
	u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
	unsigned char      iph_ihl:4,		// IP header length
		           iph_ver:4;		// IP version
	unsigned char      iph_tos;		// Type of service
	unsigned short int iph_lesn;		// IP Packet length (data + header)
	unsigned short int iph_ident;		// Identification
	unsigned short int iph_flag:3,		// Fragmentation flags
		           iph_offset:13;	// Flags offset
	unsigned char      iph_ttl; 		// Time to Live
	unsigned char      iph_protocol; 	// Protocol type
	unsigned short int iph_chksum; 		// IP datagram checksum
	struct  in_addr    iph_sourceip; 	// Source IP address
	struct  in_addr    iph_destip;   	// Destination IP address
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	printf("[Etheret Header]\n");
	printf("- Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("- Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);


	if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
		struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
		printf("[IP Header]\n");
		printf("- src ip: %s\n", inet_ntoa(ip->iph_sourceip));   
		printf("- dst ip: %s\n", inet_ntoa(ip->iph_destip));

		if (ip->iph_protocol == IPPROTO_TCP) {	// TCP Header
			printf("[TCP Header]\n");
			struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + (ip->iph_ihl & 0x0F) * 4);
			printf("- src port: %d\n", ntohs(tcp->th_sport));
			printf("- dst port: %d\n\n", ntohs(tcp->th_dport));
		}	
	}
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net;

	// Step 1: Open live pcap session on NIC with name enp0s3
	handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	if (pcap_setfilter(handle, &fp) != 0) {
		pcap_perror(handle, "Error:");
		exit(EXIT_FAILURE);
	}

	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);   // Close the handle
	return 0;
}
