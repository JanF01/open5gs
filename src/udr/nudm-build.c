
#include "nudm-build.h"

ogs_sbi_message_t *
udr_nudm_sdm_build_blockchain_node_id(void *context,
    ogs_sbi_stream_t *stream, void *data)
{
    OpenAPI_sdm_blockchain_credentials_response_t *resp =
        (OpenAPI_sdm_blockchain_credentials_response_t *)data;

    ogs_assert(resp);
    ogs_sbi_message_t sendmsg;
    memset(&sendmsg, 0, sizeof(sendmsg));

    sendmsg.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    sendmsg.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NUDM_SDM;
    sendmsg.h.api.version = (char *)OGS_SBI_API_V1;

    sendmsg.h.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_SUBSCRIPTION_DATA;
    sendmsg.h.resource.component[1] = (char *)OGS_SBI_RESOURCE_NAME_SDM_BLOCKCHAIN_NODE_ID;


    sendmsg.SdmBlockchainCredentialsResponse = resp;

    ogs_sbi_request_t *request = ogs_sbi_build_request(&sendmsg);
    ogs_assert(request);

    return request;
}
