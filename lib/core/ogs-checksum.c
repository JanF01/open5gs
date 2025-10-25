#include "ogs-core.h"
#include <string.h>

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

/* Standard Internet Checksum (RFC 1071) */
uint16_t ogs_checksum(uint16_t *addr, int len)
{
    int sum = 0;
    uint16_t *w = addr;
    int nleft = len;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
    uint16_t tmp = 0;
    *((unsigned char *)&tmp) = *(unsigned char *)w;
    sum += tmp;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

/* TCP Checksum with Pseudo-header */
uint16_t ogs_tcp_checksum(uint32_t saddr, uint32_t daddr, uint16_t *buf, int len)
{
    uint32_t sum = 0;
    uint16_t *w = buf;
    int nleft = len;

    // Add pseudo-header
    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(len);

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&sum) += *(unsigned char *)w;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}