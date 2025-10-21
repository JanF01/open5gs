
#ifndef UDR_NUDM_BUILD_H
#define UDR_NUDM_BUILD_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

ogs_sbi_message_t * udr_nudm_sdm_build_blockchain_node_id(void *context,
    ogs_sbi_stream_t *stream, void *data);


#ifdef __cplusplus
}
#endif

#endif /* UDR_NUDM_BUILD_H */
