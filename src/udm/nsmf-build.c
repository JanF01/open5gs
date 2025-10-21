
#include "nsmf-build.h"


ogs_sbi_message_t *
udm_smf_build_blockchain_credentials_response(void *context,
    ogs_sbi_stream_t *stream, void *data)
{
    OpenAPI_sdm_blockchain_credentials_response_t *resp =
        (OpenAPI_sdm_blockchain_credentials_response_t *)data;

    ogs_assert(resp);
    ogs_sbi_message_t *msg = ogs_sbi_message_new();

    msg->SdmBlockchainCredentialsResponse = resp;
    msg->h.service.name = OGS_SBI_SERVICE_NAME_NSMF_BLOCKCHAIN;
    msg->h.resource.component[0] = OGS_SBI_RESOURCE_NAME_SMF_BLOCKCHAIN_CREDENTIALS_RESPONSE;
    msg->h.method = OGS_SBI_HTTP_METHOD_POST;

    return msg;
}