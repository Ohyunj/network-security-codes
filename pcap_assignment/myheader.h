#ifndef MYHEADER_H
#define MYHEADER_H

#include <sys/types.h>
#include <netinet/in.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,
                       iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* ICMP Header */
struct icmpheader {
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};

/* UDP Header */
struct udpheader {
    u_int16_t udp_sport;
    u_int16_t udp_dport;
    u_int16_t udp_ulen;
    u_int16_t udp_sum;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

/* Pseudo TCP header */
struct pseudo_tcp {
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[1500];
};

#endif

