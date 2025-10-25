
#if !defined(OGS_CORE_INSIDE) && !defined(OGS_CORE_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_CHECKSUM_H
#define OGS_CHECKSUM_H

#ifdef __cplusplus
extern "C" {
#endif

uint16_t ogs_checksum(uint16_t *addr, int len);
uint16_t ogs_tcp_checksum(uint32_t saddr, uint32_t daddr, uint16_t *buf, int len);

#ifdef __cplusplus
}
#endif

#endif /* OGS_CHECKSUM_H */