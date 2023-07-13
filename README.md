# pcap-test
## pcap-test.c
### pcap-test.c 추가 설명
1. header 위치 정하기 </br>
아래는 ethernet_header와 ipv4_header, tcp_header를 정의한 것을 의미한다. </br>
아래의 사진을 보면 각 데이터 버퍼가 ehternet, ip,tcp,payload가 하나의 버퍼로 이루어진 것을 볼 수 있다. </br>
이와 같이 통신을 할때 header와 payload 구성이 아래의 사진과 같다고 생각을 하고 각각의 ethernet,ip,tcp header가 가리키고 있는 주소를 시작위치로 설정하고 
구조체에 넣어서 데이터를 저장하였다.  </br>

![imag](https://d2.naver.com/content/images/2015/06/helloworld-47667-2.png)
출처 : https://d2.naver.com/helloworld/47667

```c
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
```
 </br> </br>
2. payload 데이터 뽑기 </br>
payload의 경우에는 앞서 했던 것처럼 현재 packet의 위치에서 각각의 header 길이만큼을 구해서 더하면 payload 시작 위치를 알 수 있다. </br>
이를 이용해서 payload에 접근해 데이터를 뽑는 순서로 진행하였다. </br>
내가 어려웠다고 생각하는 부분은 payload_length를 구하는 부분이다. </br>
이 부분이 특히 어려웠던 건 header->caplen이 의미하는 바를 정확하게 이해하지 못하였기 때문이라고 생각한다. </br>
결론은 header 구조체에는 caplen 과 len 이 있는데 caplen의 경우에는 읽어온 페이로드의 길이를 len은 페이로드 전체 길이를 의미한다. </br>
따라서 내가 읽어온 페이로드의 길이에서 각각의 헤더를 빼주면 페이로드의 위치를 알 수 있게 된다. </br>
```
        u_char* payload = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
        printf("%x\n",header->caplen);
        int payload_length = header->caplen - (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));

        printf("Payload data\n");
        for (int i = 0; i < (payload_length > 10 ? 10 : payload_length); i++) {
            printf("%02x ", *(payload + i));
        }
        printf("\n");
```

 </br> </br> </br>
### pcap-test.c 전체 코드
```c
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_IP 0x800

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void printMac(uint8_t* m) {
    char format[] = "%02x:%02x:%02x:%02x:%02x:%02x";
    printf(format, m[0], m[1], m[2], m[3], m[4], m[5]);
}

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
        struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

        printMac(eth_hdr->ether_shost);
        printf(" ");
        printMac(eth_hdr->ether_dhost);
        printf("\n");

        printf("Source IP Address: %s\n", inet_ntoa(ipv4_hdr->ip_src));
        printf("Destination IP Address: %s\n", inet_ntoa(ipv4_hdr->ip_dst));

        printf("Source Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_hdr->th_dport));

        u_char* payload = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
        printf("%x\n",header->caplen);
        int payload_length = header->caplen - (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));

        printf("Payload data\n");
        for (int i = 0; i < (payload_length > 10 ? 10 : payload_length); i++) {
            printf("%02x ", *(payload + i));
        }
        printf("\n");

        if (ntohs(eth_hdr->ether_type) != ETHER_TYPE_IP) {
            continue;
        }
    }

    pcap_close(pcap);
    return 0;
}

```
