
#include "nudm-build.h"

ogs_sbi_request_t *
udr_nudm_sdm_build_blockchain_node_id(void *context, void *data)
{
    ogs_assert(context);
    ogs_assert(data);

    udr_sbi_ctx_t *ctx = (udr_sbi_ctx_t *)context;
    OpenAPI_sdm_blockchain_credentials_response_t *resp =
        (OpenAPI_sdm_blockchain_credentials_response_t *)data;

    ogs_assert(ctx->supi);
    ogs_assert(resp);

    ogs_sbi_message_t sendmsg;
    memset(&sendmsg, 0, sizeof(sendmsg));

    sendmsg.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    sendmsg.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NUDM_SDM;
    sendmsg.h.api.version = (char *)OGS_SBI_API_V2;

    sendmsg.h.resource.component[0] = (char *)ctx->supi;
    sendmsg.h.resource.component[1] = (char *)OGS_SBI_RESOURCE_NAME_SDM_BLOCKCHAIN_NODE_ID;

    sendmsg.SdmBlockchainCredentialsResponse = resp;

    ogs_sbi_request_t *request = ogs_sbi_build_request(&sendmsg);
    ogs_assert(request);

    return request;
}
