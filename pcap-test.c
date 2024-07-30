//#include "pcap-test.h"
#include <stdbool.h>
#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

#define ETHERTYPE_IP 0x0800

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac_address(const u_int8_t* mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(const struct in_addr* ip) {
	printf("%s", inet_ntoa(*ip));
}

void print_data(const u_char* data, int size) {
	for (int i = 0; i < size && i < 20; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
		if (ip_hdr->ip_p != IPPROTO_TCP) continue;

		//struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4);

		printf("Ethernet Header\n");
		printf("Src MAC: "); print_mac_address(eth_hdr->ether_shost); printf("\n");
		printf("Dst MAC: "); print_mac_address(eth_hdr->ether_dhost); printf("\n");

		printf("IP Header\n");
		printf("Src IP: "); print_ip_address(&ip_hdr->ip_src); printf("\n");
		printf("Dst IP: "); print_ip_address(&ip_hdr->ip_dst); printf("\n");

		printf("TCP Header\n");
		printf("Src Port: %d\n", ntohs(tcp_hdr->th_sport));
		printf("Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

		printf("Payload (Hex): ");
		const u_char* payload = (packet + sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
		int payload_size = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
		if (payload_size > 0) {
		    print_data(payload, payload_size);
		} else {
		    printf("None\n");
		}

		printf("\n");
	}

	pcap_close(pcap);
	return 0;
}

