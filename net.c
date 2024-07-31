#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>

#define MAX_PAYLOAD_SIZE 20

void print_payload(const u_char *payload, int len) {
    printf("Payload (first %d bytes):\n", MAX_PAYLOAD_SIZE);
    for (int i = 0; i < len && i < MAX_PAYLOAD_SIZE; i++) {
        printf("%c", isprint(payload[i]) ? payload[i] : '.');
    }
    printf("\n\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ether_header *eth_header = (struct ether_header *) packet;
    printf("Ethernet Header\n");
    printf("\tSource MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
    printf("\tDestination MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    printf("IP Header\n");
    printf("\tSource IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("\tDestination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    if (ip_header->ip_p != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    int tcp_header_length = tcp_header->doff * 4;
    printf("TCP Header\n");
    printf("\tSource Port: %d\n", ntohs(tcp_header->source));
    printf("\tDestination Port: %d\n", ntohs(tcp_header->dest));
    
    int payload_offset = sizeof(struct ether_header) + sizeof(struct ip) + tcp_header_length;
    int payload_length = header->caplen - payload_offset;
    const u_char *payload = packet + payload_offset;

    print_payload(payload, payload_length);
}

int main() {
    const char *dev = "ens33";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    printf("Device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    while (1) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (packet == NULL) {
            printf("Failed to capture a packet\n");
            continue;
        }
        packet_handler(NULL, &header, packet);
    }

    pcap_close(handle);
    return 0;
}

