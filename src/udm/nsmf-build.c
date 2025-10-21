
#include "nsmf-build.h"


ogs_sbi_request_t *udm_smf_build_blockchain_credentials_response(udm_ue_t *udm_ue, void *data)
{
    ogs_assert(udm_ue);
    OpenAPI_sdm_blockchain_credentials_response_t *resp =
        (OpenAPI_sdm_blockchain_credentials_response_t *)data;
    ogs_assert(resp);

    ogs_sbi_message_t sendmsg;
    memset(&sendmsg, 0, sizeof(sendmsg));

    sendmsg.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    sendmsg.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NSMF_BLOCKCHAIN;
    sendmsg.h.api.version = (char *)OGS_SBI_API_V1;

    sendmsg.h.resource.component[0] =
        (char *)OGS_SBI_RESOURCE_NAME_SMF_BLOCKCHAIN_CREDENTIALS;
    sendmsg.h.resource.component[1] = udm_ue->supi;

    sendmsg.SdmBlockchainCredentialsResponse = resp;

    ogs_sbi_request_t *request = ogs_sbi_build_request(&sendmsg);
    ogs_assert(request);

    return request;
}