/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-pfcp.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

static int decode_ipv6_header(
    struct ip6_hdr *ip6_h, uint8_t *proto, uint16_t *hlen)
{
    int done = 0;
    uint8_t *p, *jp, *endp;
    uint8_t nxt; /* Next Header */

    ogs_assert(ip6_h);
    ogs_assert(proto);
    ogs_assert(hlen);

    nxt = ip6_h->ip6_nxt;
    p = (uint8_t *)ip6_h + sizeof(*ip6_h);
    endp = p + be16toh(ip6_h->ip6_plen);

    jp = p + sizeof(struct ip6_hbh);
    while (p == endp)
    { /* Jumbo Frame */
        uint32_t jp_len = 0;
        struct ip6_opt_jumbo *jumbo = NULL;

        ogs_assert(nxt == 0);

        jumbo = (struct ip6_opt_jumbo *)jp;
        memcpy(&jp_len, jumbo->ip6oj_jumbo_len, sizeof(jp_len));
        jp_len = be32toh(jp_len);
        switch (jumbo->ip6oj_type)
        {
        case IP6OPT_JUMBO:
            endp = p + jp_len;
            break;
        case 0:
            jp++;
            break;
        default:
            jp += (sizeof(struct ip6_opt) + jp_len);
            break;
        }
    }

    while (p < endp)
    {
        struct ip6_ext *ext = (struct ip6_ext *)p;
        switch (nxt)
        {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        case 135: /* mobility */
        case 139: /* host identity, experimental */
        case 140: /* shim6 */
        case 253: /* testing, experimental */
        case 254: /* testing, experimental */
            p += ((ext->ip6e_len << 3) + 8);
            break;
        case IPPROTO_FRAGMENT:
            p += sizeof(struct ip6_frag);
            break;
        case IPPROTO_AH:
            p += ((ext->ip6e_len + 2) << 2);
            break;
        default: /* Upper Layer */
            done = 1;
            break;
        }
        if (done)
            break;

        nxt = ext->ip6e_nxt;
    }

    *proto = nxt;
    *hlen = p - (uint8_t *)ip6_h;

    return OGS_OK;
}

ogs_pfcp_rule_t *ogs_pfcp_pdr_rule_find_by_packet(
    ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *pkbuf)
{
    struct ip *ip_h = NULL;
    struct ip6_hdr *ip6_h = NULL;
    uint32_t *src_addr = NULL;
    uint32_t *dst_addr = NULL;
    int addr_len = 0;
    uint8_t proto = 0;
    uint16_t ip_hlen = 0;

    ogs_pfcp_rule_t *rule = NULL;

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);
    ogs_assert(pkbuf->data);

    ogs_list_for_each(&pdr->rule_list, rule)
    {
        int k;
        uint32_t src_mask[4];
        uint32_t dst_mask[4];
        ogs_ipfw_rule_t *ipfw = NULL;

        ipfw = &rule->ipfw;
        ogs_assert(ipfw);

        ip_h = (struct ip *)pkbuf->data;
        if (ip_h->ip_v == 4)
        {
            ip_h = (struct ip *)pkbuf->data;
            ip6_h = NULL;

            proto = ip_h->ip_p;
            ip_hlen = (ip_h->ip_hl) * 4;

            src_addr = (void *)&ip_h->ip_src.s_addr;
            dst_addr = (void *)&ip_h->ip_dst.s_addr;
            addr_len = OGS_IPV4_LEN;
        }
        else if (ip_h->ip_v == 6)
        {
            ip_h = NULL;
            ip6_h = (struct ip6_hdr *)pkbuf->data;

            decode_ipv6_header(ip6_h, &proto, &ip_hlen);

            src_addr = (void *)ip6_h->ip6_src.s6_addr;
            dst_addr = (void *)ip6_h->ip6_dst.s6_addr;
            addr_len = OGS_IPV6_LEN;
        }
        else
        {
            ogs_error("Invalid packet [IP version:%d, Packet Length:%d]",
                      ip_h->ip_v, pkbuf->len);
            ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
            continue;
        }

        ogs_trace("PROTO:%d SRC:%08x %08x %08x %08x",
                  proto, be32toh(src_addr[0]), be32toh(src_addr[1]),
                  be32toh(src_addr[2]), be32toh(src_addr[3]));
        ogs_trace("HLEN:%d  DST:%08x %08x %08x %08x",
                  ip_hlen, be32toh(dst_addr[0]), be32toh(dst_addr[1]),
                  be32toh(dst_addr[2]), be32toh(dst_addr[3]));

        ogs_trace("PROTO:%d SRC:%d-%d DST:%d-%d",
                  ipfw->proto,
                  ipfw->port.src.low,
                  ipfw->port.src.high,
                  ipfw->port.dst.low,
                  ipfw->port.dst.high);
        ogs_trace("SRC:%08x %08x %08x %08x/%08x %08x %08x %08x",
                  be32toh(ipfw->ip.src.addr[0]),
                  be32toh(ipfw->ip.src.addr[1]),
                  be32toh(ipfw->ip.src.addr[2]),
                  be32toh(ipfw->ip.src.addr[3]),
                  be32toh(ipfw->ip.src.mask[0]),
                  be32toh(ipfw->ip.src.mask[1]),
                  be32toh(ipfw->ip.src.mask[2]),
                  be32toh(ipfw->ip.src.mask[3]));
        ogs_trace("DST:%08x %08x %08x %08x/%08x %08x %08x %08x",
                  be32toh(ipfw->ip.dst.addr[0]),
                  be32toh(ipfw->ip.dst.addr[1]),
                  be32toh(ipfw->ip.dst.addr[2]),
                  be32toh(ipfw->ip.dst.addr[3]),
                  be32toh(ipfw->ip.dst.mask[0]),
                  be32toh(ipfw->ip.dst.mask[1]),
                  be32toh(ipfw->ip.dst.mask[2]),
                  be32toh(ipfw->ip.dst.mask[3]));

        for (k = 0; k < 4; k++)
        {
            src_mask[k] = src_addr[k] & ipfw->ip.src.mask[k];
            dst_mask[k] = dst_addr[k] & ipfw->ip.dst.mask[k];
        }

        if (memcmp(src_mask, ipfw->ip.src.addr, addr_len) == 0 &&
            memcmp(dst_mask, ipfw->ip.dst.addr, addr_len) == 0)
        {
            /* Protocol match */
            if (ipfw->proto == 0)
            { /* IP */
                /* No need to match port */
                return rule;
            }

            if (ipfw->proto == proto)
            {
                if (ipfw->proto == IPPROTO_TCP)
                {
                    struct tcphdr *tcph =
                        (struct tcphdr *)((char *)pkbuf->data + ip_hlen);

                    /* Source port */
                    if (ipfw->port.src.low &&
                        be16toh(tcph->th_sport) < ipfw->port.src.low)
                    {
                        continue;
                    }

                    if (ipfw->port.src.high &&
                        be16toh(tcph->th_sport) > ipfw->port.src.high)
                    {
                        continue;
                    }

                    /* Dst Port*/
                    if (ipfw->port.dst.low &&
                        be16toh(tcph->th_dport) < ipfw->port.dst.low)
                    {
                        continue;
                    }

                    if (ipfw->port.dst.high &&
                        be16toh(tcph->th_dport) > ipfw->port.dst.high)
                    {
                        continue;
                    }

                    /* Matched */
                    return rule;
                }
                else if (ipfw->proto == IPPROTO_UDP)
                {
                    struct udphdr *udph =
                        (struct udphdr *)((char *)pkbuf->data + ip_hlen);

                    /* Source port */
                    if (ipfw->port.src.low &&
                        be16toh(udph->uh_sport) < ipfw->port.src.low)
                    {
                        continue;
                    }

                    if (ipfw->port.src.high &&
                        be16toh(udph->uh_sport) > ipfw->port.src.high)
                    {
                        continue;
                    }

                    /* Dst Port*/
                    if (ipfw->port.dst.low &&
                        be16toh(udph->uh_dport) < ipfw->port.dst.low)
                    {
                        continue;
                    }

                    if (ipfw->port.dst.high &&
                        be16toh(udph->uh_dport) > ipfw->port.dst.high)
                    {
                        continue;
                    }

                    /* Matched */
                    return rule;
                }
                else
                {

                    /* No need to match port */
                    return rule;
                }
            }
        }
    }

    return NULL;
}

/* new */
bool ogs_pfcp_blockchain_json_find_by_packet(ogs_pkbuf_t *pkbuf,
                                             ogs_pfcp_blockchain_data_t *blockchain)
{
    struct ip *ip_h = NULL;
    struct tcphdr *tcph = NULL;
    uint16_t ip_hlen = 0;
    uint16_t dst_port = 0;
    char dst_ip_str[INET_ADDRSTRLEN];

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);
    ogs_assert(pkbuf->data);

    memset(blockchain, 0, sizeof(*blockchain));

    ip_h = (struct ip *)pkbuf->data;

    if (ip_h->ip_v == 4)
    {
        ip_hlen = (ip_h->ip_hl) * 4;
        OGS_INET_NTOP(&ip_h->ip_dst.s_addr, dst_ip_str);

        if (strcmp(dst_ip_str, "10.45.0.1") == 0 && ip_h->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcphdr *)((char *)pkbuf->data + ip_hlen);
            dst_port = be16toh(tcph->th_dport);

            if (dst_port == 9500)
            {
                char *payload = (char *)pkbuf->data + ip_hlen + (tcph->th_off * 4);
                int payload_len = pkbuf->len - ip_hlen - (tcph->th_off * 4);

                if (payload_len <= 0 || payload_len > pkbuf->len)
                    return false;

                char tmp_payload[4096];
                int copy_len = (payload_len < (int)sizeof(tmp_payload) - 1) ? payload_len : (int)sizeof(tmp_payload) - 1;
                memcpy(tmp_payload, payload, copy_len);
                tmp_payload[copy_len] = '\0';

                char *json_start = strchr(tmp_payload, '{');
                if (!json_start)
                {
                    ogs_error("Cannot find JSON body in payload");
                    ogs_info("Payload dump:\n%.*s", copy_len, tmp_payload);
                    return false;
                }

                ogs_info("JSON body: %s", json_start);

                /* Parse login and password */
                char login[OGS_PFCP_MAX_LOGIN_LEN];
                char password[OGS_PFCP_MAX_PASSWORD_LEN];

                if (sscanf(json_start,
                           "{\"login\":\"%[^\"]\",\"password\":\"%[^\"]\"}",
                           login, password) == 2)
                {
                    strncpy((char *)blockchain->login, login, sizeof(blockchain->login) - 1);
                    ((char *)blockchain->login)[sizeof(blockchain->login) - 1] = '\0';

                    strncpy((char *)blockchain->password, password, sizeof(blockchain->password) - 1);
                    ((char *)blockchain->password)[sizeof(blockchain->password) - 1] = '\0';

                    blockchain->login_len = strlen((char *)blockchain->login);
                    blockchain->password_len = strlen((char *)blockchain->password);

                    return true;
                }
            }
        }
    }

    return false;
}

ogs_pkbuf_t *ogs_pfcp_form_json_tcp_packet(uint32_t src_ip,
                                           uint16_t src_port,
                                           uint32_t dst_ip,
                                           uint16_t dst_port,
                                           const char *json_payload)
{

    size_t payload_len = strlen(json_payload);
    size_t ip_hdr_len = sizeof(struct ip);
    size_t tcp_hdr_len = sizeof(struct tcphdr);
    size_t total_len = ip_hdr_len + tcp_hdr_len + payload_len;

    ogs_pkbuf_t *buf = ogs_pkbuf_alloc(packet_pool, total_len + OGS_TUN_MAX_HEADROOM);
    if (!buf) {
        ogs_error("Failed to allocate packet buffer");
        return NULL;
    }

    ogs_pkbuf_reserve(buf, OGS_TUN_MAX_HEADROOM);
    ogs_pkbuf_put(buf, total_len);
    uint8_t *pkt = buf->data;

    /* IPv4 header */
    struct ip *ip_h = (struct ip *)pkt;
    ip_h->ip_v = 4;
    ip_h->ip_hl = ip_hdr_len / 4;
    ip_h->ip_tos = 0;
    ip_h->ip_len = htons(total_len);
    ip_h->ip_id = htons(0);
    ip_h->ip_off = 0;
    ip_h->ip_ttl = 64;
    ip_h->ip_p = IPPROTO_TCP;
    ip_h->ip_src.s_addr = src_ip;
    ip_h->ip_dst.s_addr = dst_ip;
    ip_h->ip_sum = 0;
    ip_h->ip_sum = ogs_checksum((uint16_t *)ip_h, ip_hdr_len);

    /* TCP header */
    struct tcphdr *tcp_h = (struct tcphdr *)(pkt + ip_hdr_len);
    tcp_h->th_sport = htons(src_port);
    tcp_h->th_dport = htons(dst_port);
    tcp_h->th_seq = htonl(1);
    tcp_h->th_ack = htonl(0);
    tcp_h->th_off = tcp_hdr_len / 4;
    tcp_h->th_flags = TH_PUSH | TH_ACK;
    tcp_h->th_win = htons(65535);
    tcp_h->th_sum = 0;
    tcp_h->th_urp = 0;

    /* Copy JSON payload */
    memcpy((uint8_t *)(tcp_h + 1), json_payload, payload_len);

    /* Compute TCP checksum */
    tcp_h->th_sum = ogs_tcp_checksum(src_ip, dst_ip, (uint16_t *)tcp_h,
                                     tcp_hdr_len + payload_len);

    return buf;
}