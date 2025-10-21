
#ifndef UDM_NSMF_BUILD_H
#define UDM_NSMF_BUILD_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

ogs_sbi_message_t *
udm_smf_build_blockchain_credentials_response(void *context,
    ogs_sbi_stream_t *stream, void *data);

#ifdef __cpluspluss
}
#endif

#endif /* UDM_NSMF_BUILD_H */