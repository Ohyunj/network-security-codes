#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

#define SIZE_ETHERNET 14
#define SNAP_LEN 1518
#define DEFAULT_FILTER "tcp"
#define HTTP_PREVIEW_LEN 512

static void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_tcp_flags(u_char flags)
{
    printf("Flags: ");
    if (flags & TH_SYN) printf("SYN ");
    if (flags & TH_ACK) printf("ACK ");
    if (flags & TH_FIN) printf("FIN ");
    if (flags & TH_RST) printf("RST ");
    if (flags & TH_PUSH) printf("PSH ");
    if (flags & TH_URG) printf("URG ");
    if (flags & TH_ECE) printf("ECE ");
    if (flags & TH_CWR) printf("CWR ");
    printf("\n");
}

static int looks_like_http(const u_char *payload, int payload_len)
{
    if (payload_len <= 0) return 0;

    const char *methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "PATCH ", "HTTP/1.0", "HTTP/1.1", "HTTP/2"
    };
    int i;

    for (i = 0; i < (int)(sizeof(methods) / sizeof(methods[0])); i++) {
        size_t len = strlen(methods[i]);
        if (payload_len >= (int)len && memcmp(payload, methods[i], len) == 0) {
            return 1;
        }
    }
    return 0;
}

static void print_payload_ascii(const u_char *payload, int payload_len)
{
    int i;
    int limit = payload_len < HTTP_PREVIEW_LEN ? payload_len : HTTP_PREVIEW_LEN;

    for (i = 0; i < limit; i++) {
        unsigned char c = payload[i];
        if (c == '\r') {
            printf("\\r");
        } else if (c == '\n') {
            printf("\\n\n");
        } else if (isprint(c) || c == '\t') {
            putchar(c);
        } else {
            putchar('.');
        }
    }

    if (payload_len > HTTP_PREVIEW_LEN) {
        printf("\n... (payload truncated, total %d bytes)\n", payload_len);
    } else {
        printf("\n");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;

    const struct ethheader *eth = (const struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    const struct ipheader *ip = (const struct ipheader *)(packet + SIZE_ETHERNET);
    int ip_header_len = ip->iph_ihl * 4;

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    const struct tcpheader *tcp = (const struct tcpheader *)(packet + SIZE_ETHERNET + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;
    int total_ip_len = ntohs(ip->iph_len);
    int payload_len = total_ip_len - ip_header_len - tcp_header_len;

    if (ip_header_len < 20 || tcp_header_len < 20 || payload_len < 0) {
        return;
    }

    const u_char *payload = packet + SIZE_ETHERNET + ip_header_len + tcp_header_len;

    printf("\n==================== PACKET ====================\n");
    printf("Captured length: %u bytes\n", header->caplen);

    printf("[Ethernet Header]\n");
    printf("Dst MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");
    printf("Src MAC: ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("[IP Header]\n");
    printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));
    printf("IP Header Length : %d bytes\n", ip_header_len);
    printf("Total IP Length  : %d bytes\n", total_ip_len);

    printf("[TCP Header]\n");
    printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %u\n", ntohs(tcp->tcp_dport));
    printf("Seq Num : %u\n", ntohl(tcp->tcp_seq));
    printf("Ack Num : %u\n", ntohl(tcp->tcp_ack));
    printf("TCP Header Length: %d bytes\n", tcp_header_len);
    print_tcp_flags(tcp->tcp_flags);

    printf("[Application Data]\n");
    printf("Payload Length: %d bytes\n", payload_len);

    if (payload_len > 0) {
        if (looks_like_http(payload, payload_len) ||
            ntohs(tcp->tcp_sport) == 80 || ntohs(tcp->tcp_dport) == 80 ||
            ntohs(tcp->tcp_sport) == 8080 || ntohs(tcp->tcp_dport) == 8080 ||
            ntohs(tcp->tcp_sport) == 8000 || ntohs(tcp->tcp_dport) == 8000) {
            printf("HTTP Message Preview:\n");
            print_payload_ascii(payload, payload_len);
        } else {
            printf("Non-HTTP TCP payload detected.\n");
        }
    } else {
        printf("No payload\n");
    }
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *dev;
    char *filter_exp = DEFAULT_FILTER;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;

    if (argc >= 2) {
        dev = argv[1];
    } else {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "[ERROR] Could not find default device: %s\n", errbuf);
            fprintf(stderr, "Usage: sudo ./pcap_programming <interface> [filter]\n");
            return 1;
        }
    }

    if (argc >= 3) {
        filter_exp = argv[2];
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERROR] pcap_open_live failed on %s: %s\n", dev, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "[ERROR] pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[ERROR] pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("===============================================\n");
    printf("PCAP Programming Assignment Sniffer\n");
    printf("Interface : %s\n", dev);
    printf("Filter    : %s\n", filter_exp);
    printf("Press Ctrl + C to stop.\n");
    printf("===============================================\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

