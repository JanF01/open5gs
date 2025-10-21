
#include "nudm-build.h"

ogs_sbi_message_t *
udr_nudm_sdm_build_blockchain_node_id(void *context,
    ogs_sbi_stream_t *stream, void *data)
{
    OpenAPI_sdm_blockchain_credentials_response_t *resp =
        (OpenAPI_sdm_blockchain_credentials_response_t *)data;

    ogs_assert(resp);
    ogs_sbi_message_t *msg = ogs_sbi_message_new();

    msg->SdmBlockchainCredentialsResponse = resp;
    msg->h.service.name = OGS_SBI_SERVICE_NAME_NUDM_SDM;
    msg->h.resource.component[0] = OGS_SBI_RESOURCE_NAME_SDM_BLOCKCHAIN_CREDENTIALS;
    msg->h.method = OGS_SBI_HTTP_METHOD_POST;

    return msg;
}
